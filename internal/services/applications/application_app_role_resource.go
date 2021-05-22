package applications

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-azuread/internal/utils"
	graphErrors "github.com/manicminer/hamilton/errors"
	"github.com/manicminer/hamilton/msgraph"

	"github.com/hashicorp/terraform-provider-azuread/internal/clients"
	"github.com/hashicorp/terraform-provider-azuread/internal/helpers"
	"github.com/hashicorp/terraform-provider-azuread/internal/services/applications/parse"
	applicationsValidate "github.com/hashicorp/terraform-provider-azuread/internal/services/applications/validate"
	"github.com/hashicorp/terraform-provider-azuread/internal/tf"
	"github.com/hashicorp/terraform-provider-azuread/internal/validate"
)

func applicationAppRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: applicationAppRoleResourceCreateUpdate,
		UpdateContext: applicationAppRoleResourceCreateUpdate,
		ReadContext:   applicationAppRoleResourceRead,
		DeleteContext: applicationAppRoleResourceDelete,

		Importer: tf.ValidateResourceIDPriorToImport(func(id string) error {
			_, err := parse.AppRoleID(id)
			return err
		}),

		Schema: map[string]*schema.Schema{
			"application_object_id": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateDiagFunc: validate.UUID,
			},

			"allowed_member_types": {
				Type:     schema.TypeSet,
				Required: true,
				MinItems: 1,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					ValidateFunc: validation.StringInSlice(
						[]string{"User", "Application"},
						false,
					),
				},
			},

			"description": {
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validate.NoEmptyStrings,
			},

			"display_name": {
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validate.NoEmptyStrings,
			},

			"enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			"role_id": {
				Type:             schema.TypeString,
				Optional:         true,
				Computed:         true,
				ForceNew:         true,
				ValidateDiagFunc: validate.UUID,
			},

			"value": {
				Type:             schema.TypeString,
				Optional:         true,
				ValidateDiagFunc: applicationsValidate.RoleScopeClaimValue,
			},
		},
	}
}

func applicationAppRoleResourceCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).Applications.ApplicationsClient

	objectId := d.Get("application_object_id").(string)

	var roleId string
	if v, ok := d.GetOk("role_id"); ok {
		roleId = v.(string)
	} else {
		rid, err := uuid.GenerateUUID()
		if err != nil {
			return tf.ErrorDiagF(err, "Generating App Role for application with object ID %q", objectId)
		}
		roleId = rid
	}

	allowedMemberTypes := make([]msgraph.AppRoleAllowedMemberType, 0)
	for _, a := range d.Get("allowed_member_types").(*schema.Set).List() {
		allowedMemberTypes = append(allowedMemberTypes, msgraph.AppRoleAllowedMemberType(a.(string)))
	}

	role := msgraph.AppRole{
		AllowedMemberTypes: &allowedMemberTypes,
		ID:                 utils.String(roleId),
		Description:        utils.String(d.Get("description").(string)),
		DisplayName:        utils.String(d.Get("display_name").(string)),
		IsEnabled:          utils.Bool(d.Get("enabled").(bool)),
	}

	if v, ok := d.GetOk("value"); ok {
		role.Value = utils.String(v.(string))
	}

	id := parse.NewAppRoleID(objectId, roleId)

	tf.LockByName(applicationResourceName, id.ObjectId)
	defer tf.UnlockByName(applicationResourceName, id.ObjectId)

	app, status, err := client.Get(ctx, id.ObjectId)
	if err != nil {
		if status == http.StatusNotFound {
			return tf.ErrorDiagPathF(nil, "application_object_id", "Application with object ID %q was not found", id.ObjectId)
		}
		return tf.ErrorDiagPathF(err, "application_object_id", "Retrieving Application with object ID %q", id.ObjectId)
	}

	if d.IsNewResource() {
		if err := app.AppendAppRole(role); err != nil {
			if _, ok := err.(*graphErrors.AlreadyExistsError); ok {
				return tf.ImportAsExistsDiag("azuread_application_app_role", id.String())
			}
			return tf.ErrorDiagF(err, "Failed to add App Role")
		}
	} else {
		existing, err := helpers.AppRoleFindById(app, id.RoleId)
		if err != nil {
			return tf.ErrorDiagPathF(nil, "role_id", "retrieving App Role with ID %q for Application %q: %+v", id.RoleId, id.ObjectId, err)
		}
		if existing == nil {
			return tf.ErrorDiagPathF(nil, "role_id", "App Role with ID %q was not found for Application %q", id.RoleId, id.ObjectId)
		}

		if app.UpdateAppRole(role) != nil {
			return tf.ErrorDiagF(err, "Updating App Role with ID %q", *role.ID)
		}
	}

	properties := msgraph.Application{
		ID:       app.ID,
		AppRoles: app.AppRoles,
	}
	if _, err := client.Update(ctx, properties); err != nil {
		return tf.ErrorDiagF(err, "Updating Application with ID %q", id.ObjectId)
	}

	d.SetId(id.String())

	return applicationAppRoleResourceRead(ctx, d, meta)
}

func applicationAppRoleResourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).Applications.ApplicationsClient

	id, err := parse.AppRoleID(d.Id())
	if err != nil {
		return tf.ErrorDiagPathF(err, "id", "Parsing App Role ID %q", d.Id())
	}

	app, status, err := client.Get(ctx, id.ObjectId)
	if err != nil {
		if status == http.StatusNotFound {
			log.Printf("[DEBUG] Application with Object ID %q was not found - removing from state!", id.ObjectId)
			d.SetId("")
			return nil
		}
		return tf.ErrorDiagPathF(err, "application_object_id", "Retrieving Application with object ID %q", id.ObjectId)
	}

	role, err := helpers.AppRoleFindById(app, id.RoleId)
	if err != nil {
		return tf.ErrorDiagF(err, "Identifying App Role")
	}

	if role == nil {
		log.Printf("[DEBUG] App Role %q (ID %q) was not found - removing from state!", id.RoleId, id.ObjectId)
		d.SetId("")
		return nil
	}

	tf.Set(d, "allowed_member_types", role.AllowedMemberTypes)
	tf.Set(d, "application_object_id", id.ObjectId)
	tf.Set(d, "description", role.Description)
	tf.Set(d, "display_name", role.DisplayName)
	tf.Set(d, "enabled", role.IsEnabled)
	tf.Set(d, "role_id", id.RoleId)
	tf.Set(d, "value", role.Value)

	return nil
}

func applicationAppRoleResourceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).Applications.ApplicationsClient

	id, err := parse.AppRoleID(d.Id())
	if err != nil {
		return tf.ErrorDiagPathF(err, "id", "Parsing App Role ID %q", d.Id())
	}

	tf.LockByName(applicationResourceName, id.ObjectId)
	defer tf.UnlockByName(applicationResourceName, id.ObjectId)

	app, status, err := client.Get(ctx, id.ObjectId)
	if err != nil {
		if status == http.StatusNotFound {
			return tf.ErrorDiagPathF(fmt.Errorf("Application was not found"), "application_object_id", "Retrieving Application with ID %q", id.ObjectId)
		}
		return tf.ErrorDiagPathF(err, "application_object_id", "Retrieving Application with ID %q", id.ObjectId)
	}

	role, err := helpers.AppRoleFindById(app, id.RoleId)
	if err != nil {
		return tf.ErrorDiagF(err, "Identifying App Role")
	}

	if role == nil {
		log.Printf("[DEBUG] App Role %q (ID %q) was not found - removing from state!", id.RoleId, id.ObjectId)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Disabling App Role %q for Application %q prior to removal", id.RoleId, id.ObjectId)
	role.IsEnabled = utils.Bool(false)
	if app.UpdateAppRole(*role) != nil {
		return tf.ErrorDiagF(err, "Disabling App Role with ID %q", *role.ID)
	}

	properties := msgraph.Application{
		ID:       app.ID,
		AppRoles: app.AppRoles,
	}
	if _, err := client.Update(ctx, properties); err != nil {
		return tf.ErrorDiagF(err, "Disabling App Role with ID %q", *role.ID)
	}

	log.Printf("[DEBUG] Removing App Role %q from Application %q", id.RoleId, id.ObjectId)
	if app.RemoveAppRole(*role) != nil {
		return tf.ErrorDiagF(err, "Removing App Role with ID %q", *role.ID)
	}

	properties.AppRoles = app.AppRoles
	if _, err := client.Update(ctx, properties); err != nil {
		return tf.ErrorDiagF(err, "Updating application to remove App Role with ID %q", *role.ID)
	}

	return nil
}
