package abnormal

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type ListVendorsParams struct {
	PageSize   int
	PageNumber int
}

type PaginatedVendors struct {
	Vendors        []VendorRef `json:"vendors"`
	PageNumber     int         `json:"pageNumber"`
	NextPageNumber int         `json:"nextPageNumber"`
}

type VendorRef struct {
	VendorDomain string `json:"vendorDomain"`
}

type VendorDetail struct {
	VendorDomain      string   `json:"vendorDomain"`
	RiskLevel         string   `json:"riskLevel"`
	VendorContacts    []string `json:"vendorContacts"`
	CompanyContacts   []string `json:"companyContacts"`
	VendorCountries   []string `json:"vendorCountries"`
	Analysis          []string `json:"analysis"`
	VendorIPAddresses []string `json:"vendorIpAddresses"`
}

type VendorActivity struct {
	EventTimeline []map[string]any `json:"eventTimeline"`
}

type ListVendorCasesParams struct {
	Filter     string
	PageSize   int
	PageNumber int
}

type PaginatedVendorCases struct {
	VendorCases    []VendorCaseRef `json:"vendorCases"`
	PageNumber     int             `json:"pageNumber"`
	NextPageNumber int             `json:"nextPageNumber"`
}

type VendorCaseRef struct {
	VendorCaseID int `json:"vendorCaseId"`
}

type VendorCaseDetails struct {
	VendorCaseID      int              `json:"vendorCaseId"`
	VendorDomain      string           `json:"vendorDomain"`
	FirstObservedTime string           `json:"firstObservedTime"`
	LastModifiedTime  string           `json:"lastModifiedTime"`
	Insights          []map[string]any `json:"insights"`
	Timeline          []map[string]any `json:"timeline"`
}

func (c *client) ListVendors(ctx context.Context, params ListVendorsParams) (PaginatedVendors, error) {
	q := url.Values{}
	if params.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(params.PageSize))
	}
	if params.PageNumber > 0 {
		q.Set("pageNumber", strconv.Itoa(params.PageNumber))
	}
	var out PaginatedVendors
	err := c.doJSON(ctx, http.MethodGet, "/vendors", q, nil, &out)
	return out, err
}

func (c *client) GetVendorDetails(ctx context.Context, vendorDomain string) (VendorDetail, error) {
	var out VendorDetail
	err := c.doJSON(ctx, http.MethodGet, "/vendors/"+url.PathEscape(vendorDomain)+"/details", nil, nil, &out)
	return out, err
}

func (c *client) GetVendorActivity(ctx context.Context, vendorDomain string) (VendorActivity, error) {
	var out VendorActivity
	err := c.doJSON(ctx, http.MethodGet, "/vendors/"+url.PathEscape(vendorDomain)+"/activity", nil, nil, &out)
	return out, err
}

func (c *client) ListVendorCases(ctx context.Context, params ListVendorCasesParams) (PaginatedVendorCases, error) {
	q := url.Values{}
	if params.Filter != "" {
		q.Set("filter", params.Filter)
	}
	if params.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(params.PageSize))
	}
	if params.PageNumber > 0 {
		q.Set("pageNumber", strconv.Itoa(params.PageNumber))
	}
	var out PaginatedVendorCases
	err := c.doJSON(ctx, http.MethodGet, "/vendor-cases", q, nil, &out)
	return out, err
}

func (c *client) GetVendorCase(ctx context.Context, caseID string) (VendorCaseDetails, error) {
	var out VendorCaseDetails
	err := c.doJSON(ctx, http.MethodGet, "/vendor-cases/"+url.PathEscape(caseID), nil, nil, &out)
	return out, err
}
