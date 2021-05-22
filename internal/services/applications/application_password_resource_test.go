package applications_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-azuread/internal/acceptance"
	"github.com/hashicorp/terraform-provider-azuread/internal/acceptance/check"
	"github.com/hashicorp/terraform-provider-azuread/internal/clients"
	"github.com/hashicorp/terraform-provider-azuread/internal/services/applications/parse"
	"github.com/hashicorp/terraform-provider-azuread/internal/utils"
)

type ApplicationPasswordResource struct{}

func TestAccApplicationPassword_basic(t *testing.T) {
	data := acceptance.BuildTestData(t, "azuread_application_password", "test")
	r := ApplicationPasswordResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basic(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("end_date").Exists(),
				check.That(data.ResourceName).Key("key_id").Exists(),
				check.That(data.ResourceName).Key("start_date").Exists(),
				check.That(data.ResourceName).Key("value").Exists(),
			),
		},
	})
}

func (r ApplicationPasswordResource) Exists(ctx context.Context, clients *clients.Client, state *terraform.InstanceState) (*bool, error) {
	id, err := parse.PasswordID(state.ID)
	if err != nil {
		return nil, fmt.Errorf("parsing Application Password ID: %v", err)
	}

	app, status, err := clients.Applications.ApplicationsClient.Get(ctx, id.ObjectId)
	if err != nil {
		if status == http.StatusNotFound {
			return nil, fmt.Errorf("Application with object ID %q does not exist", id.ObjectId)
		}
		return nil, fmt.Errorf("failed to retrieve Application with object ID %q: %+v", id.ObjectId, err)
	}

	if app.PasswordCredentials != nil {
		for _, cred := range *app.PasswordCredentials {
			if cred.KeyId != nil && *cred.KeyId == id.KeyId {
				return utils.Bool(true), nil
			}
		}
	}

	return nil, fmt.Errorf("Password Credential %q was not found for Application %q", id.KeyId, id.ObjectId)
}

func (r ApplicationPasswordResource) basic(data acceptance.TestData) string {
	return fmt.Sprintf(`
resource "azuread_application" "test" {
  name = "acctestAppPassword-%[1]d"
}

resource "azuread_application_password" "test" {
  application_object_id = azuread_application.test.object_id
}
`, data.RandomInteger)
}
