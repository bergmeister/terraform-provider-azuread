package domains

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-azuread/internal/clients"
	"github.com/hashicorp/terraform-provider-azuread/internal/tf"
)

func domainsDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: domainsDataSourceRead,

		Schema: map[string]*schema.Schema{
			"include_unverified": {
				Type:          schema.TypeBool,
				Optional:      true,
				ConflictsWith: []string{"only_default", "only_initial"}, // default or initial domains have to be verified
			},
			"only_default": {
				Type:          schema.TypeBool,
				Optional:      true,
				ConflictsWith: []string{"only_initial"},
			},
			"only_initial": {
				Type:          schema.TypeBool,
				Optional:      true,
				ConflictsWith: []string{"only_default"},
			},
			"domains": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"domain_name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"authentication_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"is_default": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"is_initial": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"is_verified": {
							Type:     schema.TypeBool,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func domainsDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).Domains.DomainsClient

	result, _, err := client.List(ctx)
	if err != nil {
		return tf.ErrorDiagF(err, "Could not list domains")
	}

	// TODO v2.0 improve the ID format
	//filterHash := base64.RawStdEncoding.EncodeToString([]byte(filter))
	//id := fmt.Sprintf("domains-%s-%s", client.BaseClient.TenantId, filterHash)
	//d.SetId(id)

	d.SetId("domains-" + client.BaseClient.TenantId)

	// TODO: v2.0 support filtering on isAdminManaged, isRoot and supportedServices
	onlyDefault := d.Get("only_default").(bool)
	onlyInitial := d.Get("only_initial").(bool)
	includeUnverified := d.Get("include_unverified").(bool)

	var domains []interface{}
	if result != nil {
		for _, v := range *result {
			if onlyDefault && v.IsDefault != nil && !*v.IsDefault {
				continue
			}
			if onlyInitial && v.IsInitial != nil && !*v.IsInitial {
				continue
			}
			if !includeUnverified && v.IsVerified != nil && !*v.IsVerified {
				continue
			}

			domains = append(domains, map[string]interface{}{
				"domain_name":         v.ID,
				"authentication_type": v.AuthenticationType,
				"is_default":          v.IsDefault,
				"is_initial":          v.IsInitial,
				"is_verified":         v.IsVerified,
			})
		}
	}

	if len(domains) == 0 {
		return tf.ErrorDiagF(err, "No domains found for the provided filters")
	}

	tf.Set(d, "domains", domains)

	return nil
}
