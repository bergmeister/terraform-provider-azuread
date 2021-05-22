package applications

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/manicminer/hamilton/msgraph"

	"github.com/hashicorp/terraform-provider-azuread/internal/clients"
	"github.com/hashicorp/terraform-provider-azuread/internal/helpers"
	applicationsValidate "github.com/hashicorp/terraform-provider-azuread/internal/services/applications/validate"
	"github.com/hashicorp/terraform-provider-azuread/internal/tf"
	"github.com/hashicorp/terraform-provider-azuread/internal/utils"
	"github.com/hashicorp/terraform-provider-azuread/internal/validate"
)

const applicationResourceName = "azuread_application"

func applicationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: applicationResourceCreate,
		ReadContext:   applicationResourceRead,
		UpdateContext: applicationResourceUpdate,
		DeleteContext: applicationResourceDelete,

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(5 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(5 * time.Minute),
			Delete: schema.DefaultTimeout(5 * time.Minute),
		},

		Importer: tf.ValidateResourceIDPriorToImport(func(id string) error {
			if _, err := uuid.ParseUUID(id); err != nil {
				return fmt.Errorf("specified ID (%q) is not valid: %s", id, err)
			}
			return nil
		}),

		Schema: map[string]*schema.Schema{
			"display_name": {
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validate.NoEmptyStrings,
			},

			"api": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true, // TODO: v2.0 remove Computed
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						// TODO: v2.0 also consider another computed typemap attribute `oauth2_permission_scope_ids` for easier consumption
						"oauth2_permission_scope": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"id": {
										Type:     schema.TypeString,
										Required: true,
									},

									"admin_consent_description": {
										Type:             schema.TypeString,
										Optional:         true,
										ValidateDiagFunc: validate.NoEmptyStrings,
									},

									"admin_consent_display_name": {
										Type:             schema.TypeString,
										Optional:         true,
										ValidateDiagFunc: validate.NoEmptyStrings,
									},

									"enabled": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  true,
									},

									"type": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  string(msgraph.PermissionScopeTypeUser),
										ValidateFunc: validation.StringInSlice([]string{
											string(msgraph.PermissionScopeTypeAdmin),
											string(msgraph.PermissionScopeTypeUser),
										}, false),
									},

									"user_consent_description": {
										Type:             schema.TypeString,
										Optional:         true,
										ValidateDiagFunc: validate.NoEmptyStrings,
									},

									"user_consent_display_name": {
										Type:             schema.TypeString,
										Optional:         true,
										ValidateDiagFunc: validate.NoEmptyStrings,
									},

									"value": {
										Type:             schema.TypeString,
										Optional:         true,
										ValidateDiagFunc: applicationsValidate.RoleScopeClaimValue,
									},
								},
							},
						},
					},
				},
			},

			// TODO: v2.0 consider another computed typemap attribute `app_role_ids` for easier consumption
			"app_role": {
				Type:       schema.TypeSet,
				Optional:   true,
				Computed:   true, // TODO: v2.0 remove computed?
				ConfigMode: schema.SchemaConfigModeAttr,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.IsUUID,
						},

						"allowed_member_types": {
							Type:     schema.TypeSet,
							Required: true,
							MinItems: 1,
							Elem: &schema.Schema{
								Type: schema.TypeString,
								ValidateFunc: validation.StringInSlice(
									[]string{
										string(msgraph.AppRoleAllowedMemberTypeApplication),
										string(msgraph.AppRoleAllowedMemberTypeUser),
									}, false,
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

						"value": {
							Type:             schema.TypeString,
							Optional:         true,
							ValidateDiagFunc: applicationsValidate.RoleScopeClaimValue,
						},
					},
				},
			},

			"fallback_public_client_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// TODO: v2.0 make this a set/list - in v1.x we only allow a single value but we concatenate multiple values on read
			"group_membership_claims": {
				Type:       schema.TypeString,
				Optional:   true,
				Deprecated: "[NOTE] This attribute will become a list in version 2.0 of the AzureAD provider",
				ValidateFunc: validation.StringInSlice([]string{
					string(msgraph.GroupMembershipClaimAll),
					string(msgraph.GroupMembershipClaimNone),
					string(msgraph.GroupMembershipClaimApplicationGroup),
					string(msgraph.GroupMembershipClaimDirectoryRole),
					string(msgraph.GroupMembershipClaimSecurityGroup),
				}, false),
			},

			"identifier_uris": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type:             schema.TypeString,
					ValidateDiagFunc: validate.IsAppURI,
				},
			},

			"optional_claims": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"access_token": schemaOptionalClaims(),
						"id_token":     schemaOptionalClaims(),
						// TODO: enable when https://github.com/Azure/azure-sdk-for-go/issues/9714 resolved
						//       or at v2.0, whichever comes first
						//"saml2_token": schemaOptionalClaims(),
					},
				},
			},

			"owners": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true, // TODO: v2.0 maybe remove Computed
				Elem: &schema.Schema{
					Type:             schema.TypeString,
					ValidateDiagFunc: validate.NoEmptyStrings,
				},
			},

			"required_resource_access": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"resource_app_id": {
							Type:     schema.TypeString,
							Required: true,
						},

						"resource_access": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"id": {
										Type:             schema.TypeString,
										Required:         true,
										ValidateDiagFunc: validate.UUID,
									},

									"type": {
										Type:     schema.TypeString,
										Required: true,
										ValidateFunc: validation.StringInSlice(
											[]string{
												string(msgraph.ResourceAccessTypeRole),
												string(msgraph.ResourceAccessTypeScope),
											},
											false, // force case sensitivity
										),
									},
								},
							},
						},
					},
				},
			},

			"sign_in_audience": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  string(msgraph.SignInAudienceAzureADMyOrg),
				ValidateFunc: validation.StringInSlice([]string{
					string(msgraph.SignInAudienceAzureADMyOrg),
					string(msgraph.SignInAudienceAzureADMultipleOrgs),
					//string(msgraph.SignInAudienceAzureADandPersonalMicrosoftAccount), // TODO: v2.0 enable this value
				}, false),
			},

			"web": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true, // TODO: v2.0 remove Computed
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"homepage_url": {
							Type:             schema.TypeString,
							Optional:         true,
							ValidateDiagFunc: validate.IsHTTPOrHTTPSURL,
						},

						"logout_url": {
							Type:             schema.TypeString,
							Optional:         true,
							ValidateDiagFunc: validate.IsHTTPOrHTTPSURL,
						},

						"redirect_uris": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Schema{
								Type:             schema.TypeString,
								ValidateDiagFunc: validate.NoEmptyStrings,
							},
						},

						"implicit_grant": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"access_token_issuance_enabled": {
										Type:     schema.TypeBool,
										Optional: true,
									},

									// TODO: v2.0 support `id_token_issuance_enabled`
								},
							},
						},
					},
				},
			},

			"application_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"object_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"prevent_duplicate_names": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
		},
	}
}

func applicationResourceCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).Applications.ApplicationsClient
	displayName := d.Get("display_name").(string)

	if d.Get("prevent_duplicate_names").(bool) {
		existingApp, err := helpers.ApplicationFindByName(ctx, client, displayName)
		if err != nil {
			return tf.ErrorDiagPathF(err, "display_name", "Could not check for existing application(s)")
		}
		if existingApp != nil {
			if existingApp.ID == nil {
				return tf.ErrorDiagF(errors.New("API returned application with nil object ID during duplicate name check"), "Bad API response")
			}
			return tf.ImportAsDuplicateDiag("azuread_application", *existingApp.ID, displayName)
		}
	}

	// TODO v2.0 remove this and use expand func for `api` block
	oauth2PermissionScopes, hasOauth2PermissionScopes := d.GetOk("api.0.oauth2_permission_scope")

	if err := applicationValidateRolesScopes(d.Get("app_role").(*schema.Set).List(), oauth2PermissionScopes.(*schema.Set).List()); err != nil {
		return tf.ErrorDiagPathF(err, "app_role", "Checking for duplicate app role / oauth2_permissions values")
	}

	properties := msgraph.Application{
		Api:                    &msgraph.ApplicationApi{},
		DisplayName:            utils.String(displayName),
		IdentifierUris:         tf.ExpandStringSlicePtr(d.Get("identifier_uris").([]interface{})),
		OptionalClaims:         expandApplicationOptionalClaims(d.Get("optional_claims").([]interface{})),
		RequiredResourceAccess: expandApplicationRequiredResourceAccess(d.Get("required_resource_access").(*schema.Set).List()),
		SignInAudience:         msgraph.SignInAudience(d.Get("sign_in_audience").(string)),
		Web: &msgraph.ApplicationWeb{
			ImplicitGrantSettings: &msgraph.ImplicitGrantSettings{},
		},
	}

	if v, ok := d.GetOk("app_role"); ok {
		properties.AppRoles = expandApplicationAppRoles(v.(*schema.Set).List())
	}

	if v, ok := d.GetOk("group_membership_claims"); ok {
		properties.GroupMembershipClaims = expandApplicationGroupMembershipClaims(v)
	}

	// TODO: v2.0 use an expand func for the `web` block
	if v, ok := d.GetOk("web.0.homepage_url"); ok {
		properties.Web.HomePageUrl = utils.String(v.(string))
	}

	// TODO: v2.0 use an expand func for the `web` block
	if v, ok := d.GetOk("web.0.logout_url"); ok {
		properties.Web.LogoutUrl = utils.String(v.(string))
	}

	// TODO: v2.0 use an expand func for the `api` block
	if hasOauth2PermissionScopes {
		properties.Api.OAuth2PermissionScopes = expandApplicationOAuth2Permissions(oauth2PermissionScopes.(*schema.Set).List())
	}

	// TODO: v2.0 use an expand func for the `implicit_grant` block
	if v, ok := d.GetOk("web.0.implicit_grant.0.access_token_issuance_enabled"); ok {
		properties.Web.ImplicitGrantSettings.EnableAccessTokenIssuance = utils.Bool(v.(bool))
	}

	if v, ok := d.GetOk("fallback_public_client_enabled"); ok {
		properties.IsFallbackPublicClient = utils.Bool(v.(bool))
	}

	// TODO: v2.0 use expand func for `web` block
	if v, ok := d.GetOk("web.0.redirect_uris"); ok {
		properties.Web.RedirectUris = tf.ExpandStringSlicePtr(v.(*schema.Set).List())
	}

	app, _, err := client.Create(ctx, properties)
	if err != nil {
		return tf.ErrorDiagF(err, "Could not create application")
	}

	if app.ID == nil || *app.ID == "" {
		return tf.ErrorDiagF(errors.New("Bad API response"), "Object ID returned for application is nil/empty")
	}

	d.SetId(*app.ID)

	if v, ok := d.GetOk("owners"); ok {
		owners := *tf.ExpandStringSlicePtr(v.(*schema.Set).List())
		if err := helpers.ApplicationSetOwners(ctx, client, app, owners); err != nil {
			return tf.ErrorDiagPathF(err, "owners", "Could not set owners for application with object ID: %q", *app.ID)
		}
	}

	return applicationResourceRead(ctx, d, meta)
}

func applicationResourceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).Applications.ApplicationsClient
	displayName := d.Get("display_name").(string)

	if d.Get("prevent_duplicate_names").(bool) {
		existingApp, err := helpers.ApplicationFindByName(ctx, client, displayName)
		if err != nil {
			return tf.ErrorDiagPathF(err, "display_name", "Could not check for existing application(s)")
		}
		if existingApp != nil {
			if existingApp.ID == nil {
				return tf.ErrorDiagF(errors.New("API returned application with nil object ID during duplicate name check"), "Bad API response")
			}

			if *existingApp.ID != d.Id() {
				return tf.ImportAsDuplicateDiag("azuread_application", *existingApp.ID, displayName)
			}
		}
	}

	// TODO v2.0 remove this and use expand func for `api` block
	var oauth2PermissionScopes interface{}
	if d.HasChange("api.0.oauth2_permission_scope") {
		oauth2PermissionScopes = d.Get("api.0.oauth2_permission_scope")
	}

	if oauth2PermissionScopes != nil {
		if err := applicationValidateRolesScopes(d.Get("app_role").(*schema.Set).List(), oauth2PermissionScopes.(*schema.Set).List()); err != nil {
			return tf.ErrorDiagPathF(err, "app_role", "Checking for duplicate app role / oauth2_permissions values")
		}
	}

	properties := msgraph.Application{
		ID:                     utils.String(d.Id()),
		Api:                    &msgraph.ApplicationApi{},
		DisplayName:            utils.String(displayName),
		IdentifierUris:         tf.ExpandStringSlicePtr(d.Get("identifier_uris").([]interface{})),
		IsFallbackPublicClient: utils.Bool(d.Get("fallback_public_client_enabled").(bool)),
		OptionalClaims:         expandApplicationOptionalClaims(d.Get("optional_claims").([]interface{})),
		RequiredResourceAccess: expandApplicationRequiredResourceAccess(d.Get("required_resource_access").(*schema.Set).List()),
		SignInAudience:         msgraph.SignInAudience(d.Get("sign_in_audience").(string)),
		Web: &msgraph.ApplicationWeb{
			ImplicitGrantSettings: &msgraph.ImplicitGrantSettings{},
		},
	}

	if d.HasChange("group_membership_claims") {
		properties.GroupMembershipClaims = expandApplicationGroupMembershipClaims(d.Get("group_membership_claims"))
	}

	// TODO: v2.0 use an expand func for the `web` block
	if d.HasChange("web.0.homepage_url") {
		properties.Web.HomePageUrl = utils.String(d.Get("web.0.homepage_url").(string))
	}

	// TODO: v2.0 use an expand func for the `web` block
	if d.HasChange("web.0.logout_url") {
		properties.Web.LogoutUrl = utils.String(d.Get("web.0.logout_url").(string))
	}

	// TODO: v2.0 use an expand func for the `implicit_grant` block
	if d.HasChange("web.0.implicit_grant.0.access_token_issuance_enabled") {
		properties.Web.ImplicitGrantSettings.EnableAccessTokenIssuance = utils.Bool(d.Get("web.0.implicit_grant.0.access_token_issuance_enabled").(bool))
	}

	// TODO: v2.0 use expand func for `web` block
	if d.HasChange("web.0.redirect_uris") {
		properties.Web.RedirectUris = tf.ExpandStringSlicePtr(d.Get("web.0.redirect_uris").(*schema.Set).List())
	}

	if _, err := client.Update(ctx, properties); err != nil {
		return tf.ErrorDiagF(err, "Could not update application with ID: %q", d.Id())
	}

	if d.HasChange("app_role") {
		if err := helpers.ApplicationSetAppRoles(ctx, client, &properties, expandApplicationAppRoles(d.Get("app_role").(*schema.Set).List())); err != nil {
			return tf.ErrorDiagPathF(err, "app_role", "Could not set App Roles")
		}
	}

	// TODO v2.0 use expand func for `api` block
	if d.HasChange("api.0.oauth2_permission_scope") {
		if o := expandApplicationOAuth2Permissions(d.Get("api.0.oauth2_permission_scope").(*schema.Set).List()); o != nil {
			if err := helpers.ApplicationSetOAuth2PermissionScopes(ctx, client, &properties, o); err != nil {
				return tf.ErrorDiagPathF(err, "oauth2_permissions", "Could not set OAuth2 Permission Scopes")
			}
		}
	}

	if d.HasChange("owners") {
		owners := *tf.ExpandStringSlicePtr(d.Get("owners").(*schema.Set).List())
		if err := helpers.ApplicationSetOwners(ctx, client, &properties, owners); err != nil {
			return tf.ErrorDiagPathF(err, "owners", "Could not set owners for application with object ID: %q", d.Id())
		}
	}

	return nil
}

func applicationResourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).Applications.ApplicationsClient

	app, status, err := client.Get(ctx, d.Id())
	if err != nil {
		if status == http.StatusNotFound {
			log.Printf("[DEBUG] Application with Object ID %q was not found - removing from state", d.Id())
			d.SetId("")
			return nil
		}

		return tf.ErrorDiagPathF(err, "id", "Retrieving Application with object ID %q", d.Id())
	}

	tf.Set(d, "api", helpers.ApplicationFlattenApi(app.Api, false))
	tf.Set(d, "app_role", helpers.ApplicationFlattenAppRoles(app.AppRoles))
	tf.Set(d, "application_id", app.AppId)
	tf.Set(d, "display_name", app.DisplayName)
	tf.Set(d, "fallback_public_client_enabled", app.IsFallbackPublicClient)
	tf.Set(d, "group_membership_claims", helpers.ApplicationFlattenGroupMembershipClaims(app.GroupMembershipClaims))
	tf.Set(d, "identifier_uris", tf.FlattenStringSlicePtr(app.IdentifierUris))
	tf.Set(d, "object_id", app.ID)
	tf.Set(d, "optional_claims", flattenApplicationOptionalClaims(app.OptionalClaims))
	tf.Set(d, "required_resource_access", flattenApplicationRequiredResourceAccess(app.RequiredResourceAccess))
	tf.Set(d, "sign_in_audience", string(app.SignInAudience))
	tf.Set(d, "web", helpers.ApplicationFlattenWeb(app.Web))

	preventDuplicates := false
	if v := d.Get("prevent_duplicate_names").(bool); v {
		preventDuplicates = v
	}
	tf.Set(d, "prevent_duplicate_names", preventDuplicates)

	owners, _, err := client.ListOwners(ctx, *app.ID)
	if err != nil {
		return tf.ErrorDiagPathF(err, "owners", "Could not retrieve owners for application with object ID %q", *app.ID)
	}
	tf.Set(d, "owners", owners)

	return nil
}

func applicationResourceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).Applications.ApplicationsClient

	_, status, err := client.Get(ctx, d.Id())
	if err != nil {
		if status == http.StatusNotFound {
			return tf.ErrorDiagPathF(fmt.Errorf("Application was not found"), "id", "Retrieving Application with object ID %q", d.Id())
		}

		return tf.ErrorDiagPathF(err, "id", "Retrieving application with object ID %q", d.Id())
	}

	status, err = client.Delete(ctx, d.Id())
	if err != nil {
		return tf.ErrorDiagPathF(err, "id", "Deleting application with object ID %q, got status %d", d.Id(), status)
	}

	return nil
}

func expandApplicationAppRoles(input []interface{}) *[]msgraph.AppRole {
	if len(input) == 0 {
		return nil
	}

	result := make([]msgraph.AppRole, 0)
	for _, appRoleRaw := range input {
		appRole := appRoleRaw.(map[string]interface{})

		var allowedMemberTypes []msgraph.AppRoleAllowedMemberType
		for _, allowedMemberType := range appRole["allowed_member_types"].(*schema.Set).List() {
			allowedMemberTypes = append(allowedMemberTypes, msgraph.AppRoleAllowedMemberType(allowedMemberType.(string)))
		}

		newAppRole := msgraph.AppRole{
			ID:                 utils.String(appRole["id"].(string)),
			AllowedMemberTypes: &allowedMemberTypes,
			Description:        utils.String(appRole["description"].(string)),
			DisplayName:        utils.String(appRole["display_name"].(string)),
			IsEnabled:          utils.Bool(appRole["enabled"].(bool)),
		}

		if v, ok := appRole["value"]; ok {
			newAppRole.Value = utils.String(v.(string))
		}

		result = append(result, newAppRole)
	}

	return &result
}

func expandApplicationGroupMembershipClaims(in interface{}) *[]msgraph.GroupMembershipClaim {
	if in == nil {
		return nil
	}
	ret := make([]msgraph.GroupMembershipClaim, 0)
	ret = append(ret, msgraph.GroupMembershipClaim(in.(string)))
	return &ret

	// TODO: v2.0 use the following to expand a TypeSet, in v1.x this attribute is a singleton string
	//if len(in) == 0 {
	//	return nil
	//}
	//result := make([]msgraph.GroupMembershipClaim, 0)
	//for _, claimRaw := range in {
	//	result = append(result, msgraph.GroupMembershipClaim(claimRaw.(string)))
	//}
	//return &result
}

func expandApplicationOAuth2Permissions(in []interface{}) *[]msgraph.PermissionScope {
	result := make([]msgraph.PermissionScope, 0)

	for _, raw := range in {
		oauth2Permissions := raw.(map[string]interface{})

		result = append(result,
			msgraph.PermissionScope{
				AdminConsentDescription: utils.String(oauth2Permissions["admin_consent_description"].(string)),
				AdminConsentDisplayName: utils.String(oauth2Permissions["admin_consent_display_name"].(string)),
				ID:                      utils.String(oauth2Permissions["id"].(string)),
				IsEnabled:               utils.Bool(oauth2Permissions["enabled"].(bool)),
				Type:                    msgraph.PermissionScopeType(oauth2Permissions["type"].(string)),
				UserConsentDescription:  utils.String(oauth2Permissions["user_consent_description"].(string)),
				UserConsentDisplayName:  utils.String(oauth2Permissions["user_consent_display_name"].(string)),
				Value:                   utils.String(oauth2Permissions["value"].(string)),
			},
		)
	}

	return &result
}

func expandApplicationOptionalClaims(in []interface{}) *msgraph.OptionalClaims {
	result := msgraph.OptionalClaims{}

	if len(in) == 0 || in[0] == nil {
		return &result
	}

	optionalClaims := in[0].(map[string]interface{})

	result.AccessToken = expandApplicationOptionalClaim(optionalClaims["access_token"].([]interface{}))
	result.IdToken = expandApplicationOptionalClaim(optionalClaims["id_token"].([]interface{}))
	// TODO: v2.0 enable this
	//result.Saml2Token = expandApplicationOptionalClaim(optionalClaims["saml2_token"].([]interface{}))

	return &result
}

func expandApplicationOptionalClaim(in []interface{}) *[]msgraph.OptionalClaim {
	result := make([]msgraph.OptionalClaim, 0)

	for _, optionalClaimRaw := range in {
		optionalClaim := optionalClaimRaw.(map[string]interface{})

		additionalProps := make([]string, 0)
		if props, ok := optionalClaim["additional_properties"]; ok && props != nil {
			for _, prop := range props.([]interface{}) {
				additionalProps = append(additionalProps, prop.(string))
			}
		}

		newClaim := msgraph.OptionalClaim{
			Name:                 utils.String(optionalClaim["name"].(string)),
			Essential:            utils.Bool(optionalClaim["essential"].(bool)),
			AdditionalProperties: &additionalProps,
		}

		if source, ok := optionalClaim["source"].(string); ok && source != "" {
			newClaim.Source = &source
		}

		result = append(result, newClaim)
	}

	return &result
}

func expandApplicationRequiredResourceAccess(in []interface{}) *[]msgraph.RequiredResourceAccess {
	result := make([]msgraph.RequiredResourceAccess, 0)

	for _, raw := range in {
		requiredResourceAccess := raw.(map[string]interface{})

		result = append(result, msgraph.RequiredResourceAccess{
			ResourceAppId: utils.String(requiredResourceAccess["resource_app_id"].(string)),
			ResourceAccess: expandApplicationResourceAccess(
				requiredResourceAccess["resource_access"].([]interface{}),
			),
		})
	}

	return &result
}

func expandApplicationResourceAccess(in []interface{}) *[]msgraph.ResourceAccess {
	result := make([]msgraph.ResourceAccess, 0)

	for _, resourceAccessRaw := range in {
		resourceAccess := resourceAccessRaw.(map[string]interface{})

		result = append(result, msgraph.ResourceAccess{
			ID:   utils.String(resourceAccess["id"].(string)),
			Type: msgraph.ResourceAccessType(resourceAccess["type"].(string)),
		})
	}

	return &result
}

func flattenApplicationOptionalClaims(in *msgraph.OptionalClaims) interface{} {
	var result []map[string]interface{}

	if in == nil {
		return result
	}

	accessTokenClaims := flattenApplicationOptionalClaim(in.AccessToken)
	idTokenClaims := flattenApplicationOptionalClaim(in.IdToken)
	//saml2TokenClaims := flattenApplicationOptionalClaim(in.Saml2Token) // TODO: v2.0 support this

	if len(accessTokenClaims) == 0 && len(idTokenClaims) == 0 {
		return result
	}

	result = append(result, map[string]interface{}{
		"access_token": accessTokenClaims,
		"id_token":     idTokenClaims,
		//"saml2_token":  saml2TokenClaims, // TODO: v2.0 support this
	})
	return result
}

func flattenApplicationOptionalClaim(in *[]msgraph.OptionalClaim) []interface{} {
	if in == nil {
		return []interface{}{}
	}

	optionalClaims := make([]interface{}, 0)
	for _, claim := range *in {
		optionalClaim := map[string]interface{}{
			"name":                  claim.Name,
			"essential":             claim.Essential,
			"source":                "",
			"additional_properties": []string{},
		}

		if claim.Source != nil {
			optionalClaim["source"] = *claim.Source
		}

		if claim.AdditionalProperties != nil && len(*claim.AdditionalProperties) > 0 {
			optionalClaim["additional_properties"] = *claim.AdditionalProperties
		}

		optionalClaims = append(optionalClaims, optionalClaim)
	}

	return optionalClaims
}

func flattenApplicationRequiredResourceAccess(in *[]msgraph.RequiredResourceAccess) []map[string]interface{} {
	if in == nil {
		return []map[string]interface{}{}
	}

	result := make([]map[string]interface{}, 0)
	for _, requiredResourceAccess := range *in {
		resourceAppId := ""
		if requiredResourceAccess.ResourceAppId != nil {
			resourceAppId = *requiredResourceAccess.ResourceAppId
		}

		result = append(result, map[string]interface{}{
			"resource_app_id": resourceAppId,
			"resource_access": flattenApplicationResourceAccess(requiredResourceAccess.ResourceAccess),
		})
	}

	return result
}

func flattenApplicationResourceAccess(in *[]msgraph.ResourceAccess) []interface{} {
	if in == nil {
		return []interface{}{}
	}

	accesses := make([]interface{}, 0)
	for _, resourceAccess := range *in {
		access := make(map[string]interface{})
		if resourceAccess.ID != nil {
			access["id"] = *resourceAccess.ID
		}
		access["type"] = string(resourceAccess.Type)
		accesses = append(accesses, access)
	}

	return accesses
}

func applicationValidateRolesScopes(appRoles, oauth2Permissions []interface{}) error {
	var values []string

	for _, roleRaw := range appRoles {
		role := roleRaw.(map[string]interface{})
		if val := role["value"].(string); val != "" {
			values = append(values, val)
		}
	}

	for _, scopeRaw := range oauth2Permissions {
		scope := scopeRaw.(map[string]interface{})
		if val := scope["value"].(string); val != "" {
			values = append(values, val)
		}
	}

	encountered := make([]string, 0)
	for _, val := range values {
		for _, en := range encountered {
			if en == val {
				return fmt.Errorf("validation failed: duplicate value found: %q", val)
			}
		}
		encountered = append(encountered, val)
	}

	return nil
}
