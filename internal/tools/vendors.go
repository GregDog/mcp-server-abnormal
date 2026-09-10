package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type vendorDomainInput struct {
	VendorDomain string `json:"vendor_domain" jsonschema:"Vendor email domain (for example vendor.com)."`
}

type vendorItem struct {
	VendorDomain string `json:"vendor_domain"`
}

type vendorDetail struct {
	VendorDomain      string   `json:"vendor_domain"`
	RiskLevel         string   `json:"risk_level,omitempty"`
	VendorContacts    []string `json:"vendor_contacts,omitempty"`
	CompanyContacts   []string `json:"company_contacts,omitempty"`
	VendorCountries   []string `json:"vendor_countries,omitempty"`
	Analysis          []string `json:"analysis,omitempty"`
	VendorIPAddresses []string `json:"vendor_ip_addresses,omitempty"`
}

type vendorActivityResult struct {
	VendorDomain  string           `json:"vendor_domain"`
	EventTimeline []map[string]any `json:"event_timeline"`
}

type vendorCasesListInput struct {
	listInput
	Since string `json:"since,omitempty" jsonschema:"Start of lastModifiedTime filter (RFC3339). Default last 24 hours."`
	Until string `json:"until,omitempty" jsonschema:"End of lastModifiedTime filter (RFC3339). Default now."`
}

type vendorCaseItem struct {
	VendorCaseID int `json:"vendor_case_id"`
}

type vendorCaseDetail struct {
	VendorCaseID      int              `json:"vendor_case_id"`
	VendorDomain      string           `json:"vendor_domain"`
	FirstObservedTime string           `json:"first_observed_time,omitempty"`
	LastModifiedTime  string           `json:"last_modified_time,omitempty"`
	Insights          []map[string]any `json:"insights,omitempty"`
	Timeline          []map[string]any `json:"timeline,omitempty"`
}

func registerVendors(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_vendors_list",
		Title:       "List Abnormal vendors",
		Description: "List vendors your organization has interacted with.",
		Annotations: readOnly(),
	}, h.listVendors)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_vendor_get",
		Title:       "Get Abnormal vendor details",
		Description: "Get vendor profile, risk level, and contact metadata by domain.",
		Annotations: readOnly(),
	}, h.getVendor)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_vendor_activity_list",
		Title:       "List Abnormal vendor activity",
		Description: "Get activity timeline for a vendor domain.",
		Annotations: readOnly(),
	}, h.listVendorActivity)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_vendor_cases_list",
		Title:       "List Abnormal vendor cases",
		Description: "List vendor compromise cases. Always applies a lastModifiedTime filter so pagination works.",
		Annotations: readOnly(),
	}, h.listVendorCases)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_vendor_case_get",
		Title:       "Get an Abnormal vendor case",
		Description: "Get vendor case details including insights and timeline.",
		Annotations: readOnly(),
	}, h.getVendorCase)
}

func (h *handlers) listVendors(ctx context.Context, _ *mcp.CallToolRequest, in listInput) (*mcp.CallToolResult, abnormal.Page[vendorItem], error) {
	pageSize, pageNumber := pageArgs(in.Limit, in.Cursor)
	resp, err := h.api.ListVendors(ctx, abnormal.ListVendorsParams{
		PageSize: pageSize, PageNumber: pageNumber,
	})
	if err != nil {
		return nil, abnormal.Page[vendorItem]{}, abnormal.APIError(err)
	}
	items := make([]vendorItem, 0, len(resp.Vendors))
	for _, v := range resp.Vendors {
		items = append(items, vendorItem{VendorDomain: v.VendorDomain})
	}
	total := len(items)
	if resp.NextPageNumber > 0 {
		total = pageNumber * pageSize
	}
	return nil, mapPage(items, total, resp.PageNumber, resp.NextPageNumber), nil
}

func (h *handlers) getVendor(ctx context.Context, _ *mcp.CallToolRequest, in vendorDomainInput) (*mcp.CallToolResult, vendorDetail, error) {
	if in.VendorDomain == "" {
		return nil, vendorDetail{}, errVendorDomainRequired
	}
	resp, err := h.api.GetVendorDetails(ctx, in.VendorDomain)
	if err != nil {
		return nil, vendorDetail{}, abnormal.APIError(err)
	}
	return nil, vendorDetail{
		VendorDomain: resp.VendorDomain, RiskLevel: resp.RiskLevel,
		VendorContacts:    boundStrings(resp.VendorContacts, maxBoundedStrings),
		CompanyContacts:   boundStrings(resp.CompanyContacts, maxBoundedStrings),
		VendorCountries:   boundStrings(resp.VendorCountries, maxBoundedStrings),
		Analysis:          boundStrings(resp.Analysis, maxBoundedItems),
		VendorIPAddresses: boundStrings(resp.VendorIPAddresses, maxBoundedStrings),
	}, nil
}

func (h *handlers) listVendorActivity(ctx context.Context, _ *mcp.CallToolRequest, in vendorDomainInput) (*mcp.CallToolResult, vendorActivityResult, error) {
	if in.VendorDomain == "" {
		return nil, vendorActivityResult{}, errVendorDomainRequired
	}
	resp, err := h.api.GetVendorActivity(ctx, in.VendorDomain)
	if err != nil {
		return nil, vendorActivityResult{}, abnormal.APIError(err)
	}
	return nil, vendorActivityResult{
		VendorDomain:  in.VendorDomain,
		EventTimeline: boundMaps(resp.EventTimeline, maxTimelineEvents),
	}, nil
}

func (h *handlers) listVendorCases(ctx context.Context, _ *mcp.CallToolRequest, in vendorCasesListInput) (*mcp.CallToolResult, abnormal.Page[vendorCaseItem], error) {
	since, until, err := defaultSinceUntil(in.Since, in.Until)
	if err != nil {
		return nil, abnormal.Page[vendorCaseItem]{}, err
	}
	pageSize, pageNumber := pageArgs(in.Limit, in.Cursor)
	filter := abnormal.FormatTimeFilter("lastModifiedTime", since, until)
	resp, err := h.api.ListVendorCases(ctx, abnormal.ListVendorCasesParams{
		Filter: filter, PageSize: pageSize, PageNumber: pageNumber,
	})
	if err != nil {
		return nil, abnormal.Page[vendorCaseItem]{}, abnormal.APIError(err)
	}
	items := make([]vendorCaseItem, 0, len(resp.VendorCases))
	for _, c := range resp.VendorCases {
		items = append(items, vendorCaseItem{VendorCaseID: c.VendorCaseID})
	}
	total := len(items)
	if resp.NextPageNumber > 0 {
		total = pageNumber * pageSize
	}
	return nil, mapPage(items, total, resp.PageNumber, resp.NextPageNumber), nil
}

func (h *handlers) getVendorCase(ctx context.Context, _ *mcp.CallToolRequest, in getInput) (*mcp.CallToolResult, vendorCaseDetail, error) {
	if in.ID == "" {
		return nil, vendorCaseDetail{}, errIDRequired
	}
	resp, err := h.api.GetVendorCase(ctx, in.ID)
	if err != nil {
		return nil, vendorCaseDetail{}, abnormal.APIError(err)
	}
	return nil, vendorCaseDetail{
		VendorCaseID: resp.VendorCaseID, VendorDomain: resp.VendorDomain,
		FirstObservedTime: resp.FirstObservedTime, LastModifiedTime: resp.LastModifiedTime,
		Insights: boundMaps(resp.Insights, maxBoundedItems),
		Timeline: boundMaps(resp.Timeline, maxTimelineEvents),
	}, nil
}
