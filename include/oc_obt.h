/*
// Copyright (c) 2017-2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
/**
 * @file
 * Collection of functions to on board and provision clients and servers
 */
#ifndef OC_OBT_H
#define OC_OBT_H

#include "oc_acl.h"
#include "oc_api.h"
#include "oc_cred.h"
#include "oc_pki.h"
#include "oc_uuid.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * The amount of time the stack will wait for a response from a discovery
 * request.
 */
#define DISCOVERY_CB_PERIOD (60)

/**
 * Callback invoked in response to device discovery.
 *
 * Example:
 * ```
 * static void
 * get_device(oc_client_response_t *data)
 * {
 *   oc_rep_t *rep = data->payload;
 *   char *di = NULL, *n = NULL;
 *   size_t di_len = 0, n_len = 0;
 *
 *   if (oc_rep_get_string(rep, "di", &di, &di_len)) {
 *     printf("Device id: %s\n", di);
 *   }
 *   if (oc_rep_get_string(rep, "n", &n, &n_len)) {
 *     printf("Device name: %s\n", n);
 *   }
 * }
 *
 * static void
 * unowned_device_cb(oc_uuid_t *uuid, oc_endpoint_t *eps, void *data)
 * {
 *   (void)data;
 *   char di[37];
 *   oc_uuid_to_str(uuid, di, 37);
 *   oc_endpoint_t *ep = eps;
 *
 *   printf("\nDiscovered unowned device: %s at:\n", di);
 *   while (eps != NULL) {
 *     PRINTipaddr(*eps);
 *     printf("\n");
 *     eps = eps->next;
 *   }
 *
 *   oc_do_get("/oic/d", ep, NULL, &get_device, HIGH_QOS, NULL);
 * }
 *
 * oc_obt_discover_unowned_devices(unowned_device_cb, NULL);
 * ```
 * @param[in] uuid the uuid of the discovered device
 * @param[in] eps list of endpoints that can be used to connect with the
 *                discovered device
 * @param[in] data context pointer
 *
 * @see oc_obt_discover_unowned_devices
 * @see oc_obt_discover_unowned_devices_realm_local_ipv6
 * @see oc_obt_discover_unowned_devices_site_local_ipv6
 * @see oc_obt_discover_owned_devices
 * @see oc_obt_discover_owned_devices_realm_local_ipv6
 * @see oc_obt_discover_owned_devices_site_local_ipv6
 */
typedef void (*oc_obt_discovery_cb_t)(oc_uuid_t *uuid, oc_endpoint_t *eps,
                                      void *data);
typedef void (*oc_obt_device_status_cb_t)(oc_uuid_t *, int, void *);
typedef void (*oc_obt_status_cb_t)(int, void *);

/**
 * Initialize the IoTivity stack so it can be used as an onboarding tool (OBT)
 *
 * Call once at startup for OBT initialization
 *
 * Persistent storage must be initialized before calling oc_obt_init()
 *
 * example:
 * ```
 * static int
 *  app_init(void)
 *  {
 *    int ret = oc_init_platform("OCF", NULL, NULL);
 *    ret |= oc_add_device("/oic/d", "oic.d.dots", "OBT", "ocf.2.0.5",
 *                         "ocf.res.1.0.0,ocf.sh.1.0.0", NULL, NULL);
 *    oc_device_bind_resource_type(0, "oic.d.ams");
 *    oc_device_bind_resource_type(0, "oic.d.cms");
 *    return ret;
 *  }
 *
 * static void
 * issue_requests(void)
 * {
 *   oc_obt_init();
 * }
 *
 * static void
 * signal_event_loop(void)
 * {
 *   // code not shown
 * }
 * static const oc_handler_t handler = { .init = app_init,
 *                                       .signal_event_loop = signal_event_loop,
 *                                       .requests_entry = issue_requests };
 *
 * #ifdef OC_STORAGE
 *   oc_storage_config("./onboarding_tool_creds");
 * #endif // OC_STORAGE
 *   if (oc_main_init(&handler) < 0)
 *     return init;
 * ```
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_init(void);

/**
 * Free all resources associated with the onboarding tool
 *
 * Called when the OBT terminates.
 */
void oc_obt_shutdown(void);

/* Device discovery */
/**
 * Discover all unowned devices
 *
 * The discovery request will make a muli-cast request to the IPv6 link-local
 * multicast address scope and over IPv4.
 *
 * Multicast discovery over IPv4 will only happen if the stack is built with
 * the OC_IPV4 build flag.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after the
 *                 oc_obt_discover_unowned_devices function returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_unowned_devices(oc_obt_discovery_cb_t cb, void *data);

/**
 * Discover all unowned devices using the realm-local address scope
 *
 * The discovery request will make a muli-cast request to the IPv6 realm-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after
 *                 oc_obt_discover_unowned_devices returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_unowned_devices_realm_local_ipv6(oc_obt_discovery_cb_t cb,
                                                     void *data);

/**
 * Discover all unowned devices using the site-local address scope
 *
 * The discovery request will make a muli-cast request to the IPv6 site-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after
 *                 oc_obt_discover_unowned_devices returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_unowned_devices_site_local_ipv6(oc_obt_discovery_cb_t cb,
                                                    void *data);

/**
 * Discover all devices owned by the onboarding tool
 *
 * The discovery request will make a muli-cast request to the IPv6 link-local
 * multicast address scope and over IPv4.
 *
 * Multicast discovery over IPv4 will only happen if the stack is built with
 * the OC_IPV4 build flag.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after
 *                 oc_obt_discover_unowned_devices returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_owned_devices(oc_obt_discovery_cb_t cb, void *data);

/**
 * Discover all devices owned by the onboarding tool
 * using the realm-local address scope
 *
 * The discovery request will make a muli-cast request to the IPv6 realm-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after
 *                 oc_obt_discover_unowned_devices returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_owned_devices_realm_local_ipv6(oc_obt_discovery_cb_t cb,
                                                   void *data);

/**
 * Discover all devices owned by the onboarding tool
 * using the site-local address scope
 *
 * The discovery request will make a muli-cast request to the IPv6 site-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after
 *                 oc_obt_discover_unowned_devices returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_owned_devices_site_local_ipv6(oc_obt_discovery_cb_t cb,
                                                  void *data);
/**
 * Discover all resources on the device identified by its uuid.
 *
 * @param[in] uuid the uuid of the device the resources are being discovered on
 * @param[in] handler the oc_discovery_all_handler_t invoked in responce to this
 *                    discovery request
 * @param[in] data context pointer that is passed to the
 *                 oc_discovery_all_handler_t callback function. The pointer
 *                 must remain valid till the `more` parameter of the
 *                 oc_discovery_all_handler_t invoked in response to this
 *                 discover request is false.
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_discover_all_resources(oc_uuid_t *uuid,
                                  oc_discovery_all_handler_t handler,
                                  void *data);
/* Perform ownership transfer */
int oc_obt_perform_just_works_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                                  void *data);
int oc_obt_request_random_pin(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                              void *data);
int oc_obt_perform_random_pin_otm(oc_uuid_t *uuid, const unsigned char *pin,
                                  size_t pin_len, oc_obt_device_status_cb_t cb,
                                  void *data);
int oc_obt_perform_cert_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                            void *data);

/* RESET device state */
int oc_obt_device_hard_reset(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                             void *data);

/* Provision pair-wise 128-bit pre-shared keys */
int oc_obt_provision_pairwise_credentials(oc_uuid_t *uuid1, oc_uuid_t *uuid2,
                                          oc_obt_status_cb_t cb, void *data);
/* Provision identity certificates */
int oc_obt_provision_identity_certificate(oc_uuid_t *uuid,
                                          oc_obt_status_cb_t cb, void *data);

/* Provision role certificates */
int oc_obt_provision_role_certificate(oc_role_t *roles, oc_uuid_t *uuid,
                                      oc_obt_status_cb_t cb, void *data);

oc_role_t *oc_obt_add_roleid(oc_role_t *roles, const char *role,
                             const char *authority);
void oc_obt_free_roleid(oc_role_t *roles);

/* Provision access-control entries (ace2) */
oc_sec_ace_t *oc_obt_new_ace_for_subject(oc_uuid_t *uuid);
oc_sec_ace_t *oc_obt_new_ace_for_connection(oc_ace_connection_type_t conn);
oc_sec_ace_t *oc_obt_new_ace_for_role(const char *role, const char *authority);
oc_ace_res_t *oc_obt_ace_new_resource(oc_sec_ace_t *ace);
void oc_obt_ace_resource_set_href(oc_ace_res_t *resource, const char *href);
void oc_obt_ace_resource_set_wc(oc_ace_res_t *resource, oc_ace_wildcard_t wc);
void oc_obt_ace_add_permission(oc_sec_ace_t *ace,
                               oc_ace_permissions_t permission);

int oc_obt_provision_ace(oc_uuid_t *subject, oc_sec_ace_t *ace,
                         oc_obt_device_status_cb_t cb, void *data);
void oc_obt_free_ace(oc_sec_ace_t *ace);

/* Provision role ACE for wildcard "*" resource with RW permissions */
int oc_obt_provision_role_wildcard_ace(oc_uuid_t *subject, const char *role,
                                       const char *authority,
                                       oc_obt_device_status_cb_t cb,
                                       void *data);

/* Provision auth-crypt ACE for the wildcard "*" resource with RW permissions */
int oc_obt_provision_auth_wildcard_ace(oc_uuid_t *subject,
                                       oc_obt_device_status_cb_t cb,
                                       void *data);

oc_sec_creds_t *oc_obt_retrieve_own_creds(void);
int oc_obt_delete_own_cred_by_credid(int credid);

typedef void (*oc_obt_creds_cb_t)(struct oc_sec_creds_t *, void *);

int oc_obt_retrieve_creds(oc_uuid_t *subject, oc_obt_creds_cb_t cb, void *data);
void oc_obt_free_creds(oc_sec_creds_t *creds);
int oc_obt_delete_cred_by_credid(oc_uuid_t *uuid, int credid,
                                 oc_obt_status_cb_t cb, void *data);

typedef void (*oc_obt_acl_cb_t)(oc_sec_acl_t *, void *);

int oc_obt_retrieve_acl(oc_uuid_t *uuid, oc_obt_acl_cb_t cb, void *data);
void oc_obt_free_acl(oc_sec_acl_t *acl);
int oc_obt_delete_ace_by_aceid(oc_uuid_t *uuid, int aceid,
                               oc_obt_status_cb_t cb, void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_OBT_H */
