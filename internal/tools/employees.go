package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

const maxEmployeeLoginRows = 50

type employeeInput struct {
	Email string `json:"email" jsonschema:"Employee email address."`
}

type employeeDetail struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Title   string `json:"title,omitempty"`
	Manager string `json:"manager,omitempty"`
}

type employeeIdentityItem struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

type employeeIdentityResult struct {
	Email string                 `json:"email"`
	Data  []employeeIdentityItem `json:"data"`
}

type employeeLoginsInput struct {
	employeeInput
	Limit int `json:"limit,omitempty" jsonschema:"Maximum login rows to return. Default 50, maximum 50."`
}

type employeeLoginsResult struct {
	Email     string                      `json:"email"`
	Items     []abnormal.EmployeeLoginRow `json:"items"`
	Truncated bool                        `json:"truncated,omitempty"`
}

func registerEmployees(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_employee_get",
		Title:       "Get Abnormal employee profile",
		Description: "Get employee information by email address.",
		Annotations: readOnly(),
	}, h.getEmployee)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_employee_identity_get",
		Title:       "Get Abnormal employee identity analysis",
		Description: "Get employee identity analysis (Genome) data by email address.",
		Annotations: readOnly(),
	}, h.getEmployeeIdentity)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_employee_logins_list",
		Title:       "List recent Abnormal employee logins",
		Description: "Get employee login events for the last 30 days (bounded CSV parse, not raw file output).",
		Annotations: readOnly(),
	}, h.listEmployeeLogins)
}

func (h *handlers) getEmployee(ctx context.Context, _ *mcp.CallToolRequest, in employeeInput) (*mcp.CallToolResult, employeeDetail, error) {
	if in.Email == "" {
		return nil, employeeDetail{}, errEmailRequired
	}
	resp, err := h.api.GetEmployee(ctx, in.Email)
	if err != nil {
		return nil, employeeDetail{}, abnormal.APIError(err)
	}
	return nil, employeeDetail{
		Name: resp.Name, Email: resp.Email, Title: resp.Title, Manager: resp.Manager,
	}, nil
}

func (h *handlers) getEmployeeIdentity(ctx context.Context, _ *mcp.CallToolRequest, in employeeInput) (*mcp.CallToolResult, employeeIdentityResult, error) {
	if in.Email == "" {
		return nil, employeeIdentityResult{}, errEmailRequired
	}
	resp, err := h.api.GetEmployeeIdentity(ctx, in.Email)
	if err != nil {
		return nil, employeeIdentityResult{}, abnormal.APIError(err)
	}
	out := employeeIdentityResult{Email: in.Email}
	for _, d := range resp.Data {
		out.Data = append(out.Data, employeeIdentityItem{Key: d.Key, Value: d.Value})
	}
	return nil, out, nil
}

func (h *handlers) listEmployeeLogins(ctx context.Context, _ *mcp.CallToolRequest, in employeeLoginsInput) (*mcp.CallToolResult, employeeLoginsResult, error) {
	if in.Email == "" {
		return nil, employeeLoginsResult{}, errEmailRequired
	}
	limit := in.Limit
	if limit <= 0 {
		limit = maxEmployeeLoginRows
	}
	if limit > maxEmployeeLoginRows {
		limit = maxEmployeeLoginRows
	}
	rows, err := h.api.GetEmployeeLogins(ctx, in.Email, limit)
	if err != nil {
		return nil, employeeLoginsResult{}, abnormal.APIError(err)
	}
	out := employeeLoginsResult{Email: in.Email, Items: rows}
	if len(rows) >= limit {
		out.Truncated = true
	}
	return nil, out, nil
}
