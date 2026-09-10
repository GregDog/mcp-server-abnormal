package tools

import (
	"context"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRegisterAllTools(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	Register(server, &fakeAPI{}, Options{})

	t1, t2 := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := server.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "1"}, nil).Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 24 {
		t.Fatalf("tools: %d", len(tools.Tools))
	}

	want := []string{
		"abnormal_threats_list",
		"abnormal_threat_get",
		"abnormal_threat_action_get",
		"abnormal_threat_links_list",
		"abnormal_threat_attachments_list",
		"abnormal_search_messages",
		"abnormal_search_activities_list",
		"abnormal_search_activity_get",
		"abnormal_message_remediation_history",
		"abnormal_mailbox_campaigns_list",
		"abnormal_mailbox_campaign_get",
		"abnormal_mailbox_unanalyzed_list",
		"abnormal_employee_get",
		"abnormal_employee_identity_get",
		"abnormal_employee_logins_list",
		"abnormal_cases_list",
		"abnormal_case_get",
		"abnormal_case_analysis_get",
		"abnormal_case_action_get",
		"abnormal_vendors_list",
		"abnormal_vendor_get",
		"abnormal_vendor_activity_list",
		"abnormal_vendor_cases_list",
		"abnormal_vendor_case_get",
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("expected read-only annotation on %s", tool.Name)
		}
	}
	for _, name := range want {
		if !slices.Contains(names, name) {
			t.Fatalf("missing tool %s in %v", name, names)
		}
	}
}

func TestRegisterResponseTools(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	Register(server, &fakeAPI{}, Options{AllowResponse: true})

	t1, t2 := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := server.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "1"}, nil).Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 27 {
		t.Fatalf("tools: %d", len(tools.Tools))
	}

	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	for _, name := range []string{"abnormal_search_remediate", "abnormal_threat_remediate", "abnormal_case_update"} {
		if !slices.Contains(names, name) {
			t.Fatalf("missing response tool %s in %v", name, names)
		}
	}
}

func TestRegisterEvidenceTools(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	Register(server, &fakeAPI{}, Options{AllowEvidenceDownload: true})

	t1, t2 := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := server.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "1"}, nil).Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 29 {
		t.Fatalf("tools: %d", len(tools.Tools))
	}

	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	for _, name := range []string{
		"abnormal_message_eml_get",
		"abnormal_search_message_eml_get",
		"abnormal_message_attachment_get",
		"abnormal_message_attachment_download",
		"abnormal_search_attachment_download",
	} {
		if !slices.Contains(names, name) {
			t.Fatalf("missing evidence tool %s in %v", name, names)
		}
	}
}

func TestRegisterEvidenceAndResponseTools(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	Register(server, &fakeAPI{}, Options{AllowEvidenceDownload: true, AllowResponse: true})

	t1, t2 := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := server.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "1"}, nil).Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 32 {
		t.Fatalf("tools: %d", len(tools.Tools))
	}
}
