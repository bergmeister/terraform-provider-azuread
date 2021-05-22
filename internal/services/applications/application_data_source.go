package applications

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/manicminer/hamilton/msgraph"

	"github.com/hashicorp/terraform-provider-azuread/internal/clients"
	"github.com/hashicorp/terraform-provider-azuread/internal/helpers"
	"github.com/hashicorp/terraform-provider-azuread/internal/tf"
	"github.com/hashicorp/terraform-provider-azuread/internal/validate"
)

func applicationDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: applicationDataSourceRead,

		Schema: map[string]*schema.Schema{
			"object_id": {
				Type:             schema.TypeString,
				Optional:         true,
				Computed:         true,
				ExactlyOneOf:     []string{"application_id", "display_name", "object_id"},
				ValidateDiagFunc: validate.UUID,
			},

			"application_id": {
				Type:             schema.TypeString,
				Optional:         true,
				Computed:         true,
				ExactlyOneOf:     []string{"application_id", "display_name", "object_id"},
				ValidateDiagFunc: validate.UUID,
			},

			"display_name": {
				Type:             schema.TypeString,
				Optional:         true,
				Computed:         true,
				ExactlyOneOf:     []string{"application_id", "display_name", "object_id"},
				ValidateDiagFunc: validate.NoEmptyStrings,
			},

			"api": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						// TODO: v2.0 also consider another computed typemap attribute `oauth2_permission_scope_ids` for easier consumption
						"oauth2_permission_scopes": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"id": {
										Type:     schema.TypeString,
										Computed: true,
									},

									"admin_consent_description": {
										Type:     schema.TypeString,
										Computed: true,
									},

									"admin_consent_display_name": {
										Type:     schema.TypeString,
										Computed: true,
									},

									"enabled": {
										Type:     schema.TypeBool,
										Computed: true,
									},

									"type": {
										Type:     schema.TypeString,
										Computed: true,
									},

									"user_consent_description": {
										Type:     schema.TypeString,
										Computed: true,
									},

									"user_consent_display_name": {
										Type:     schema.TypeString,
										Computed: true,
									},

									"value": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
						},
					},
				},
			},

			// TODO: v2.0 consider another computed typemap attribute `app_role_ids` for easier consumption
			"app_roles": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"allowed_member_types": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},

						"description": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"display_name": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},

						"value": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},

			"fallback_public_client_enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},

			"group_membership_claims": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"identifier_uris": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
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
						//"saml_token": schemaOptionalClaims(),
					},
				},
			},

			"owners": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			"required_resource_access": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"resource_app_id": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"resource_access": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"id": {
										Type:     schema.TypeString,
										Computed: true,
									},

									"type": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
						},
					},
				},
			},

			"sign_in_audience": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"web": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"homepage_url": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"logout_url": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"redirect_uris": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},

						"implicit_grant": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"access_token_issuance_enabled": {
										Type:     schema.TypeBool,
										Computed: true,
									},

									// TODO: v2.0 support `id_token_issuance_enabled`
								},
							},
						},
					},
				},
			},
		},
	}
}

func applicationDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).Applications.ApplicationsClient

	var app *msgraph.Application

	if objectId, ok := d.Get("object_id").(string); ok && objectId != "" {
		var status int
		var err error
		app, status, err = client.Get(ctx, objectId)
		if err != nil {
			if status == http.StatusNotFound {
				return tf.ErrorDiagPathF(nil, "object_id", "Application with object ID %q was not found", objectId)
			}

			return tf.ErrorDiagPathF(err, "object_id", "Retrieving Application with object ID %q", objectId)
		}
	} else {
		var fieldName, fieldValue string
		if applicationId, ok := d.Get("application_id").(string); ok && applicationId != "" {
			fieldName = "appId"
			fieldValue = applicationId
		} else if displayName, ok := d.Get("display_name").(string); ok && displayName != "" {
			fieldName = "displayName"
			fieldValue = displayName
		} else {
			return tf.ErrorDiagF(nil, "One of `object_id`, `application_id` or `displayName` must be specified")
		}

		filter := fmt.Sprintf("%s eq '%s'", fieldName, fieldValue)

		result, _, err := client.List(ctx, filter)
		if err != nil {
			return tf.ErrorDiagF(err, "Listing applications for filter %q", filter)
		}

		switch {
		case result == nil || len(*result) == 0:
			return tf.ErrorDiagF(fmt.Errorf("No applications found matching filter: %q", filter), "Application not found")
		case len(*result) > 1:
			return tf.ErrorDiagF(fmt.Errorf("Found multiple applications matching filter: %q", filter), "Multiple applications found")
		}

		app = &(*result)[0]
		switch fieldName {
		case "appId":
			if app.AppId == nil {
				return tf.ErrorDiagF(fmt.Errorf("nil AppID for applications matching filter: %q", filter), "Bad API Response")
			}
			if *app.AppId != fieldValue {
				return tf.ErrorDiagF(fmt.Errorf("AppID does not match (%q != %q) for applications matching filter: %q", *app.AppId, fieldValue, filter), "Bad API Response")
			}
		case "displayName":
			if app.DisplayName == nil {
				return tf.ErrorDiagF(fmt.Errorf("nil displayName for applications matching filter: %q", filter), "Bad API Response")
			}
			if *app.DisplayName != fieldValue {
				return tf.ErrorDiagF(fmt.Errorf("DisplayName does not match (%q != %q) for applications matching filter: %q", *app.DisplayName, fieldValue, filter), "Bad API Response")
			}
		}
	}

	if app == nil {
		return tf.ErrorDiagF(fmt.Errorf("app was unexpectedly nil"), "Application not found")
	}

	if app.ID == nil {
		return tf.ErrorDiagF(fmt.Errorf("Object ID returned for application is nil"), "Bad API Response")
	}

	d.SetId(*app.ID)

	tf.Set(d, "api", helpers.ApplicationFlattenApi(app.Api, true))
	tf.Set(d, "app_roles", helpers.ApplicationFlattenAppRoles(app.AppRoles))
	tf.Set(d, "application_id", app.AppId)
	tf.Set(d, "available_to_other_tenants", app.SignInAudience == msgraph.SignInAudienceAzureADMultipleOrgs)
	tf.Set(d, "display_name", app.DisplayName)
	tf.Set(d, "fallback_public_client_enabled", app.IsFallbackPublicClient)
	tf.Set(d, "group_membership_claims", helpers.ApplicationFlattenGroupMembershipClaims(app.GroupMembershipClaims))
	tf.Set(d, "identifier_uris", tf.FlattenStringSlicePtr(app.IdentifierUris))
	tf.Set(d, "object_id", app.ID)
	tf.Set(d, "optional_claims", flattenApplicationOptionalClaims(app.OptionalClaims))
	tf.Set(d, "required_resource_access", flattenApplicationRequiredResourceAccess(app.RequiredResourceAccess))
	tf.Set(d, "sign_in_audience", string(app.SignInAudience))
	tf.Set(d, "web", helpers.ApplicationFlattenWeb(app.Web))

	owners, _, err := client.ListOwners(ctx, *app.ID)
	if err != nil {
		return tf.ErrorDiagPathF(err, "owners", "Could not retrieve owners for application with object ID %q", *app.ID)
	}
	tf.Set(d, "owners", owners)

	return nil
}
