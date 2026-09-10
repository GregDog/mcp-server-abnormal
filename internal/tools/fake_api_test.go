package tools

import (
	"context"
	"errors"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type fakeAPI struct{}

func (f *fakeAPI) ListThreats(_ context.Context, _ abnormal.ListThreatsParams) (abnormal.PaginatedThreats, error) {
	return abnormal.PaginatedThreats{
		Threats:    []abnormal.ThreatRef{{ThreatID: "threat-1"}},
		PageNumber: 1,
	}, nil
}

func (f *fakeAPI) GetThreat(_ context.Context, id string, _, _ int) (abnormal.ThreatDetails, error) {
	if id == "" {
		return abnormal.ThreatDetails{}, errors.New("missing id")
	}
	return abnormal.ThreatDetails{
		ThreatID:       id,
		RecipientCount: 1,
		Messages: []abnormal.ThreatMessage{{
			ThreatID:     id,
			AbxMessageID: 123,
			Subject:      "test",
		}},
	}, nil
}

func (f *fakeAPI) SearchMessages(_ context.Context, req abnormal.SearchRequest, _, _ int) (abnormal.SearchResponse, error) {
	return abnormal.SearchResponse{
		Results: []abnormal.SearchResult{{
			Subject: strPtr("hello"),
		}},
		Total:      1,
		PageNumber: 1,
		PageSize:   20,
	}, nil
}

func (f *fakeAPI) ListSearchActivities(_ context.Context, _ abnormal.ListActivitiesParams) (abnormal.ActivitiesResponse, error) {
	return abnormal.ActivitiesResponse{
		Activities: []abnormal.ActivityLogEntry{{ActivityID: 1, Action: "search", Status: "completed"}},
		Total:      1,
		PageNumber: 1,
		PageSize:   20,
	}, nil
}

func (f *fakeAPI) GetSearchActivityStatus(_ context.Context, id int) (abnormal.ActivityStatusResponse, error) {
	return abnormal.ActivityStatusResponse{ActivityID: id, Action: "delete", Status: "completed"}, nil
}

func (f *fakeAPI) GetRemediationHistory(_ context.Context, messageID int64) (abnormal.RemediationHistory, error) {
	return abnormal.RemediationHistory{
		RemediationHistory: map[string]string{"Auto-Remediated": "2024-01-01T00:00:00Z"},
		FolderLocations:    []string{"Junk"},
	}, nil
}

func (f *fakeAPI) ListAbuseCampaigns(_ context.Context, _ abnormal.ListAbuseCampaignsParams) (abnormal.PaginatedAbuseCampaigns, error) {
	return abnormal.PaginatedAbuseCampaigns{
		Campaigns:  []abnormal.AbuseCampaignRef{{CampaignID: "camp-1"}},
		PageNumber: 1,
	}, nil
}

func (f *fakeAPI) GetAbuseCampaign(_ context.Context, id string) (abnormal.AbuseCampaignDetails, error) {
	return abnormal.AbuseCampaignDetails{CampaignID: id, Subject: "spam"}, nil
}

func (f *fakeAPI) ListUnanalyzedMailbox(_ context.Context, _, _ string) (abnormal.AbuseMailboxUnanalyzedResponse, error) {
	return abnormal.AbuseMailboxUnanalyzedResponse{
		Results: []abnormal.AbuseMailboxUnanalyzedMessage{{
			Subject:           "fwd",
			AbxMessageID:      99,
			NotAnalyzedReason: "timeout",
		}},
	}, nil
}

func testHandlers() *handlers {
	return &handlers{api: &fakeAPI{}}
}
