package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/keycloak-auth-provider/pkg/client"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

// Keycloak's offset is a Java Integer. The shared handler binds this native
// continuation to the provider, search filter and page size, and expires it.
type groupCursor struct {
	Offset  int    `json:"offset"`
	Name    string `json:"name,omitempty"`
	AfterID string `json:"after,omitempty"`
}

// FetchGroupPage adapts native first/max paging to the existing provider contract.
// Keycloak's database defines name equality and ordering. Probe the lookahead's
// exact-name cohort by native ID, rather than guessing its collation in Go, so
// case- or accent-equivalent names cannot cross page boundaries unstably.
func FetchGroupPage(ctx context.Context, directory *client.Client, req authcommon.PageRequest) (authcommon.PageResult, error) {
	if req.Limit <= 0 || req.Limit > authcommon.MaxGroupPageSize {
		return authcommon.PageResult{}, errors.New("invalid page size")
	}
	var cursor groupCursor
	if req.Cursor != "" && json.Unmarshal([]byte(req.Cursor), &cursor) != nil {
		return authcommon.PageResult{}, fmt.Errorf("%w: invalid group offset", authcommon.ErrInvalidCursor)
	}
	const maxOffset = 1<<31 - 1
	if cursor.Offset < 0 || cursor.Offset > maxOffset-req.Limit || (cursor.Name == "" && cursor.AfterID != "") {
		return authcommon.PageResult{}, fmt.Errorf("%w: invalid group offset", authcommon.ErrInvalidCursor)
	}
	ctx, cancel := context.WithTimeout(ctx, membershipTimeout)
	defer cancel()
	items := state.GroupInfoList{}
	appendGroups := func(groups []group) {
		for _, g := range groups {
			info, _ := g.info() // readGroupPage already validated every record.
			items = append(items, info)
		}
	}
	consumeCohort := func(groups []group) error {
		if len(groups) > maxGroups {
			return errors.New("too many groups with equivalent names")
		}
		if len(groups) == 0 {
			return unresolvedGroupCohort(cursor.Name)
		}
		sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
		start := sort.Search(len(groups), func(i int) bool { return groups[i].ID > cursor.AfterID })
		end := min(start+req.Limit-len(items), len(groups))
		appendGroups(groups[start:end])
		if end < len(groups) {
			cursor.AfterID = groups[end-1].ID
		} else {
			if cursor.Offset > maxOffset-len(groups) {
				return errors.New("group offset exceeds Keycloak's limit")
			}
			cursor.Offset += len(groups)
			cursor.Name, cursor.AfterID = "", ""
		}
		return nil
	}
	// At most three reads: a prior cohort, a native window, and the boundary
	// cohort. Reuse the boundary lookup rather than fetching that cohort again.
	if cursor.Name != "" {
		groups, err := readGroupPage(ctx, directory, cursor.Name, true, 0, maxGroups+1)
		if err != nil {
			return authcommon.PageResult{}, err
		}
		if cursor.AfterID != "" && hasGroupNamePadding(cursor.Name) {
			found := false
			for _, g := range groups {
				found = found || g.ID == cursor.AfterID
			}
			if !found {
				return authcommon.PageResult{}, unresolvedGroupCohort(cursor.Name)
			}
		}
		if err := consumeCohort(groups); err != nil {
			return authcommon.PageResult{}, err
		}
	}
	if len(items) < req.Limit {
		remaining := req.Limit - len(items)
		groups, err := readGroupPage(ctx, directory, req.NameFilter, false, cursor.Offset, remaining+1)
		if err != nil {
			return authcommon.PageResult{}, err
		}
		if len(groups) <= remaining {
			appendGroups(groups)
			return authcommon.PageResult{Items: items}, nil
		}
		lookahead := groups[remaining]
		cohort, err := readGroupPage(ctx, directory, lookahead.Name, true, 0, maxGroups+1)
		if err != nil {
			return authcommon.PageResult{}, err
		}
		if len(cohort) > maxGroups {
			return authcommon.PageResult{}, errors.New("too many groups with equivalent names")
		}
		cohortIDs := make(map[string]bool, len(cohort))
		for _, g := range cohort {
			cohortIDs[g.ID] = true
		}
		if !cohortIDs[lookahead.ID] {
			return authcommon.PageResult{}, unresolvedGroupCohort(lookahead.Name)
		}
		end := remaining
		for end > 0 && cohortIDs[groups[end-1].ID] {
			end--
		}
		appendGroups(groups[:end])
		cursor.Offset += end
		if end < remaining {
			cursor.Name, cursor.AfterID = lookahead.Name, ""
			if err := consumeCohort(cohort); err != nil {
				return authcommon.PageResult{}, err
			}
		}
	}
	if len(items) != req.Limit {
		return authcommon.PageResult{}, fmt.Errorf("%w: groups changed during paging; restart browsing", authcommon.ErrInvalidCursor)
	}
	native, err := json.Marshal(cursor)
	if err != nil {
		return authcommon.PageResult{}, err
	}
	return authcommon.PageResult{Items: items, NextCursor: string(native)}, nil
}

// GroupsResource applies Java String.trim() even to exact queries. Some
// databases therefore cannot roundtrip stored names with ASCII-edge padding.
func hasGroupNamePadding(name string) bool {
	return strings.TrimFunc(name, func(r rune) bool { return r <= 0x20 }) != name
}

func unresolvedGroupCohort(name string) error {
	if hasGroupNamePadding(name) {
		return fmt.Errorf("keycloak trims surrounding whitespace from group searches; rename group %q without surrounding whitespace before browsing", name)
	}
	return fmt.Errorf("%w: group changed during paging", authcommon.ErrInvalidCursor)
}

func readGroupPage(ctx context.Context, directory *client.Client, search string, exact bool, offset, limit int) ([]group, error) {
	// A space reaches search.trim() on the qualified releases; omitting search
	// would return only roots. Keep searches flat so offsets count group records.
	if search == "" {
		search = " "
	}
	query := url.Values{
		"search":              {search},
		"exact":               {strconv.FormatBool(exact)},
		"first":               {strconv.Itoa(offset)},
		"max":                 {strconv.Itoa(limit)},
		"populateHierarchy":   {"false"},
		"briefRepresentation": {"true"},
		"subGroupsCount":      {"false"},
	}
	var page []struct {
		group
		SubGroups []json.RawMessage `json:"subGroups"`
	}
	status, err := read(ctx, directory, "/groups", query, &page)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("group listing returned HTTP %d", status)
	}
	if page == nil || len(page) > limit {
		return nil, errors.New("invalid or oversized group page")
	}
	groups := make([]group, len(page))
	seen := make(map[string]bool, len(page))
	for i, record := range page {
		if len(record.SubGroups) > 0 {
			return nil, errors.New("keycloak returned a hierarchy instead of a flat group page")
		}
		g := record.group
		if _, err := g.info(); err != nil {
			return nil, err
		}
		// An exact match can contain differently spelled names under the
		// server database's collation; only Keycloak can define that equality.
		if g.Name == "" || seen[g.ID] {
			return nil, errors.New("invalid or duplicate group in page")
		}
		seen[g.ID] = true
		groups[i] = g
	}
	return groups, nil
}
