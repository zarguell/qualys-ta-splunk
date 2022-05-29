"use strict";

define(
    ["backbone", "jquery", "splunkjs/splunk"],
    function(Backbone, jquery, splunk_js_sdk) {
        sdk = splunk_js_sdk;
        var ExampleView = Backbone.View.extend({
            // -----------------------------------------------------------------
            // Backbon Functions, These are specific to the Backbone library
            // -----------------------------------------------------------------
            initialize: function initialize() {
                Backbone.View.prototype.initialize.apply(this, arguments);
            },

            events: {
                "click .setup_button": "trigger_setup",
                "click .cancel_button": "trigger_cancel",
            },

            render: function() {
                this.el.innerHTML = this.get_template();
                fetch_configuration_file = this.fetch_configuration_file();
                this.fetch_app_configuration_file();
                show_success_message = this.show_success_message();                
                return this;
            },
            
            // Show success message on page load
            show_success_message: async function show_success_message() {
                var url_string = window.location.href;
                var url = new URL(url_string);
                var is_configured = 1;
                
                if(url_string.indexOf('&is_configured=') != -1) {
                    is_configured = url.searchParams.get("is_configured");
                    is_configured = this.sanitize_string(is_configured);
                    
                    if (is_configured == 0) {
                        var info_output_element = jquery(".container .info_output");
                        info_output_element.stop();
                        info_output_element.fadeIn();
                        info_output_element.focus();
                        
                        setTimeout(function() {
                            info_output_element.fadeOut();
                        }, 7000); // <-- time in milliseconds
                    }
                }
                
                if(url_string.indexOf('&msg=') != -1) {
                    var msg = url.searchParams.get("msg");
                    msg = this.sanitize_string(msg);

                    if (msg == 1) {
                        var success_output_element = jquery(".container .success_output");
                        success_output_element.stop();
                        success_output_element.fadeIn();
                        success_output_element.focus();
                        
                        setTimeout(function() {
                            success_output_element.fadeOut();
                        }, 7000); // <-- time in milliseconds
                    }
                }
            },

            // -----------------------------------------------------------------
            // Custom Functions, These are unrelated to the Backbone functions
            // -----------------------------------------------------------------
            // ----------------------------------
            // Main Setup Logic
            // ----------------------------------
            // This performs some sanity checking and cleanup on the inputs that
            // the user has provided before kicking off main setup process
            trigger_setup: function trigger_setup() {
                // Used to hide the error output, when a setup is retried
                this.display_error_output([]);

                var info_output_element = jquery(".container .info_output");
                info_output_element.stop();
                info_output_element.fadeOut();

                var success_output_element = jquery(".container .success_output");
                success_output_element.stop();
                success_output_element.fadeOut();

                var api_server = jquery("input[name=api_server]").val();
                api_server = this.sanitize_string(api_server);

                var ta_username = jquery("input[name=name]").val();
                ta_username = this.sanitize_string(ta_username);

                var ta_password = jquery("input[name=password]").val();
                ta_password = this.sanitize_string(ta_password);

                var ta_confirm_password = jquery("input[name=confirm_password]").val();
                ta_confirm_password = this.sanitize_string(ta_confirm_password);

                var use_ca = +jquery("input[name=use_ca]").prop('checked');

                var ca_path = jquery("input[name=ca_path]").val();
                ca_path = this.sanitize_string(ca_path);

                var ca_key = jquery("input[name=ca_key]").val();
                ca_key = this.sanitize_string(ca_key);

                var ca_pass = jquery("input[name=ca_pass]").val();
                ca_pass = this.sanitize_string(ca_pass);

                var ca_pass_confirm = jquery("input[name=ca_pass_confirm]").val();
                ca_pass_confirm = this.sanitize_string(ca_pass_confirm);

                var api_timeout = jquery("input[name=api_timeout]").val();
                api_timeout = this.sanitize_string(api_timeout);

                var log_host_summary = +jquery("input[name=log_host_summary]").prop('checked');

                var log_extra_host_summary = +jquery("input[name=log_extra_host_summary]").prop('checked');

                var log_detections = +jquery("input[name=log_detections]").prop('checked');

                var log_host_details_in_detections = +jquery("input[name=log_host_details_in_detections]").prop('checked');

                var host_fields_to_log = jquery("input[name=host_fields_to_log]").val();
                host_fields_to_log = this.sanitize_string(host_fields_to_log);

                var detection_fields_to_log = jquery("input[name=detection_fields_to_log]").val();
                detection_fields_to_log = this.sanitize_string(detection_fields_to_log);

                var detection_params = jquery("input[name=detection_params]").val();
                detection_params = this.sanitize_string(detection_params);

                var use_multi_threading = +jquery("input[name=use_multi_threading]").prop('checked');

                var max_allowed_results_field_len = jquery("input[name=max_allowed_results_field_len]").val();
                max_allowed_results_field_len = this.sanitize_string(max_allowed_results_field_len);

                var num_threads = jquery("input[name=num_threads]").val();
                num_threads = this.sanitize_string(num_threads);

                var enable_full_pull = +jquery("input[name=enable_full_pull]").prop('checked');

                var enable_seed_file_generation = +jquery("input[name=enable_seed_file_generation]").prop('checked');

                var seed_file_path = jquery("input[name=seed_file_path]").val();
                seed_file_path = this.sanitize_string(seed_file_path);

                var log_individual_findings = +jquery("input[name=log_individual_findings]").prop('checked');

                var log_webapp_summary = +jquery("input[name=log_webapp_summary]").prop('checked');

                var extra_was_params = jquery("input[name=extra_was_params]").val();
                extra_was_params = this.sanitize_string(extra_was_params);

                var use_multi_threading_for_was = +jquery("input[name=use_multi_threading_for_was]").prop('checked');

                var num_threads_for_was = jquery("input[name=num_threads_for_was]").val();
                num_threads_for_was = this.sanitize_string(num_threads_for_was);

                var log_individual_compliance_events = +jquery("input[name=log_individual_compliance_events]").prop('checked');

                var log_policy_summary = +jquery("input[name=log_policy_summary]").prop('checked');

                var pc_details = +jquery("input[name=pc_details]").prop('checked');

                var pc_extra_details = +jquery("input[name=pc_extra_details]").prop('checked');

                var pc_multi_threading_enabled = +jquery("input[name=pc_multi_threading_enabled]").prop('checked');

                var num_threads_for_pc = jquery("input[name=num_threads_for_pc]").val();
                num_threads_for_pc = this.sanitize_string(num_threads_for_pc);

                var pc_truncation_limit = jquery("input[name=pc_truncation_limit]").val();
                pc_truncation_limit = this.sanitize_string(pc_truncation_limit);

                var extra_posture_params = jquery("input[name=extra_posture_params]").val();
                extra_posture_params = this.sanitize_string(extra_posture_params);
   
                var cs_log_individual_events = +jquery("input[name=cs_log_individual_events]").prop('checked');

                var cs_log_summary_events = +jquery("input[name=cs_log_summary_events]").prop('checked');

                var cs_multi_threading_enabled = +jquery("input[name=cs_multi_threading_enabled]").prop('checked');

                var cs_num_threads = jquery("input[name=cs_num_threads]").val();
                cs_num_threads = this.sanitize_string(cs_num_threads);

                var cs_image_page_size = jquery("input[name=cs_image_page_size]").val();
                cs_image_page_size = this.sanitize_string(cs_image_page_size);

                var cs_extra_params = jquery("input[name=cs_extra_params]").val();
                cs_extra_params = this.sanitize_string(cs_extra_params);
   
                var cs_log_individual_container_events = +jquery("input[name=cs_log_individual_container_events]").prop('checked');

                var cs_log_container_summary_events = +jquery("input[name=cs_log_container_summary_events]").prop('checked');

                var cs_container_multi_threading_enabled = +jquery("input[name=cs_container_multi_threading_enabled]").prop('checked');

                var cs_container_num_threads = jquery("input[name=cs_container_num_threads]").val();
                cs_container_num_threads = this.sanitize_string(cs_container_num_threads);

                var cs_container_api_page_size = jquery("input[name=cs_container_api_page_size]").val();
                cs_container_api_page_size = this.sanitize_string(cs_container_api_page_size);

                var cs_container_extra_params = jquery("input[name=cs_container_extra_params]").val();
                cs_container_extra_params = this.sanitize_string(cs_container_extra_params);

                var fim_events_page_size = jquery("input[name=fim_events_page_size]").val();
                fim_events_page_size = this.sanitize_string(fim_events_page_size);

                var fim_events_extra_params = jquery("input[name=fim_events_extra_params]").val();
                fim_events_extra_params = this.sanitize_string(fim_events_extra_params);

                var fim_ignored_events_page_size = jquery("input[name=fim_ignored_events_page_size]").val();
                fim_ignored_events_page_size = this.sanitize_string(fim_ignored_events_page_size);

                var fim_ignored_events_extra_params = jquery("input[name=fim_ignored_events_extra_params]").val();
                fim_ignored_events_extra_params = this.sanitize_string(fim_ignored_events_extra_params);

                var fim_incidents_page_size = jquery("input[name=fim_incidents_page_size]").val();
                fim_incidents_page_size = this.sanitize_string(fim_incidents_page_size);

                var fim_incidents_extra_params = jquery("input[name=fim_incidents_extra_params]").val();
                fim_incidents_extra_params = this.sanitize_string(fim_incidents_extra_params);

                var ioc_events_pageSize = jquery("input[name=ioc_events_pageSize]").val();
                ioc_events_pageSize = this.sanitize_string(ioc_events_pageSize);

                var ioc_extra_params = jquery("input[name=ioc_extra_params]").val();
                ioc_extra_params = this.sanitize_string(ioc_extra_params);

                var al_extra_params = jquery("input[name=al_extra_params]").val();
                al_extra_params = this.sanitize_string(al_extra_params);

                var is_index_knowledgebase = +jquery("input[name=is_index_knowledgebase]").prop('checked');

                var log_kb_additional_fields = +jquery("input[name=log_kb_additional_fields]").prop('checked');

                var use_proxy = +jquery("input[name=use_proxy]").prop('checked');

                var proxy_server = jquery("input[name=proxy_server]").val();
                proxy_server = this.sanitize_string(proxy_server);

                var enable_debug = +jquery("input[name=enable_debug]").prop('checked');

                var preserve_api_output = +jquery("input[name=preserve_api_output]").prop('checked');

                var log_individual_sem_detection = +jquery("input[name=log_individual_sem_detection]").prop('checked');

                var log_sem_asset_summary = +jquery("input[name=log_sem_asset_summary]").prop('checked');

                var extra_sem_params = jquery("input[name=extra_sem_params]").val();
                extra_sem_params = this.sanitize_string(extra_sem_params);

                var sem_truncation_limit = jquery("input[name=sem_truncation_limit]").val();
                sem_truncation_limit = this.sanitize_string(sem_truncation_limit);

                var evidenceRequired = +jquery("input[name=evidenceRequired]").prop('checked');  

                var pcrs_num_count_for_pid = jquery("input[name=pcrs_num_count_for_pid]").val();
                pcrs_num_count_for_pid = this.sanitize_string(pcrs_num_count_for_pid);
                               
                var properties_to_update = {
                    api_server: api_server,
                    use_ca: use_ca,
                    ca_path: ca_path,
                    ca_key: ca_key,
                    api_timeout: api_timeout,
                    log_host_summary: log_host_summary,
                    log_extra_host_summary: log_extra_host_summary,
                    log_detections: log_detections,
                    log_host_details_in_detections: log_host_details_in_detections,
                    host_fields_to_log: host_fields_to_log,
                    detection_fields_to_log: detection_fields_to_log,
                    max_allowed_results_field_len: max_allowed_results_field_len,
                    detection_params: detection_params,
                    use_multi_threading: use_multi_threading,
                    num_threads: num_threads,
                    enable_full_pull: enable_full_pull,
                    enable_seed_file_generation: enable_seed_file_generation,
                    seed_file_path: seed_file_path,
                    log_individual_findings: log_individual_findings,
                    log_webapp_summary: log_webapp_summary,
                    extra_was_params: extra_was_params,
                    use_multi_threading_for_was: use_multi_threading_for_was,
                    num_threads_for_was: num_threads_for_was,
                    log_individual_compliance_events: log_individual_compliance_events,
                    log_policy_summary: log_policy_summary,
                    pc_details: pc_details,
                    pc_extra_details: pc_extra_details,
                    pc_multi_threading_enabled: pc_multi_threading_enabled,
                    num_threads_for_pc: num_threads_for_pc,
                    pc_truncation_limit: pc_truncation_limit,
                    extra_posture_params: extra_posture_params,
                    cs_log_individual_events: cs_log_individual_events,
                    cs_log_summary_events: cs_log_summary_events,
                    cs_multi_threading_enabled: cs_multi_threading_enabled,
                    cs_num_threads: cs_num_threads,
                    cs_image_page_size: cs_image_page_size,
                    cs_extra_params: cs_extra_params,
                    cs_log_individual_container_events: cs_log_individual_container_events,
                    cs_log_container_summary_events: cs_log_container_summary_events,
                    cs_container_multi_threading_enabled: cs_container_multi_threading_enabled,
                    cs_container_num_threads: cs_container_num_threads,
                    cs_container_api_page_size: cs_container_api_page_size,
                    cs_container_extra_params: cs_container_extra_params,
                    fim_events_page_size: fim_events_page_size,
                    fim_events_extra_params: fim_events_extra_params,
                    fim_ignored_events_page_size: fim_ignored_events_page_size,
                    fim_ignored_events_extra_params: fim_ignored_events_extra_params,
                    fim_incidents_page_size: fim_incidents_page_size,
                    fim_incidents_extra_params: fim_incidents_extra_params,
                    ioc_events_pageSize: ioc_events_pageSize,
                    ioc_extra_params: ioc_extra_params,
                    al_extra_params: al_extra_params,
                    is_index_knowledgebase: is_index_knowledgebase,
                    log_kb_additional_fields: log_kb_additional_fields,
                    use_proxy: use_proxy,
                    proxy_server: proxy_server,
                    enable_debug: enable_debug,
                    preserve_api_output: preserve_api_output,
                    log_individual_sem_detection: log_individual_sem_detection,
                    log_sem_asset_summary: log_sem_asset_summary,
                    extra_sem_params: extra_sem_params,
                    sem_truncation_limit: sem_truncation_limit,
                    evidenceRequired: evidenceRequired,
                    pcrs_num_count_for_pid: pcrs_num_count_for_pid                    
                };

                var error_messages_to_display = this.validate_inputs(
                    ta_username,
                    ta_password,
                    ta_confirm_password,
                    ca_pass,
                    ca_pass_confirm,
                    properties_to_update,
                );

                var did_error_messages_occur = error_messages_to_display.length > 0;
                if (did_error_messages_occur) {
                    // Displays the errors that occurred input validation
                    this.display_error_output(error_messages_to_display);
                } else {
                    this.perform_setup(
                        splunk_js_sdk,
                        properties_to_update,
                        ta_username,
                        ta_password,
                        ca_pass,
                        ca_pass_confirm,
                    );
                }
            },

            // Redirect to manage apps page on click on Cancel button
            trigger_cancel: function trigger_cancel() {
                var app_name = "TA-QualysCloudPlatform";
                var redirect_url = "/manager/" + app_name + "/apps/local";

                window.location.href = redirect_url;
            },
            
            // This is where the main setup process occurs
            perform_setup: async function perform_setup(splunk_js_sdk, properties_to_update, ta_username, ta_password, ca_pass, ca_pass_confirm) {
                var app_name = "TA-QualysCloudPlatform";

                var application_name_space = {
                    owner: "nobody",
                    app: app_name,
                    sharing: "app",
                };

                try {
                    // Create the Splunk JS SDK Service object
                    splunk_js_sdk_service = this.create_splunk_js_sdk_service(
                        splunk_js_sdk,
                        application_name_space,
                    );
                    
                    // Encrypt the proxy_server password in the passwords.conf file
                    if (properties_to_update["proxy_server"] != '') {
                        proxy_server = properties_to_update["proxy_server"];
                        var proxy_password = this.fetch_proxy_password(proxy_server);

                        if (proxy_password !== "") {
                            updated_proxy_server = proxy_server.replace(proxy_password, "****");
                            
                            properties_to_update["proxy_server"] = updated_proxy_server;
                            await this.encrypt_proxy_server_password(splunk_js_sdk_service, proxy_password, app_name);
                        }
                    }
                    
                    // Creates the custom configuration file of this Splunk App
                    // All required information for this Splunk App is placed in
                    // there
                    await this.create_custom_configuration_file(
                        splunk_js_sdk_service,
                        properties_to_update,
                    );
                    
                    // Creates the passwords.conf stanza that is the encryption
                    // of the api_key provided by the user
                    if (ta_username != '' && ta_password != '') {
                        await this.encrypt_qualys_password(splunk_js_sdk_service, ta_username, ta_password, app_name);
                    }
                    
                    // Encrypt the ca_pass in the passwords.conf file
                    if (ca_pass != '') {
                        await this.encrypt_ca_pass(splunk_js_sdk_service, ca_pass, app_name);
                    }
                    
                    // Completes the setup, by access the app.conf's [install]
                    // stanza and then setting the `is_configured` to true
                    await this.complete_setup(splunk_js_sdk_service);

                    // Refresh the setup form
                    this.refresh_splunk_app_setuppage(app_name);
                } catch (error) {
                    // This could be better error catching.
                    // Usually, error output that is ONLY relevant to the user
                    // should be displayed. This will return output that the
                    // user does not understand, causing them to be confused.
                    var error_messages_to_display = [];
                    if (
                        error !== null &&
                        typeof error === "object" &&
                        error.hasOwnProperty("responseText")
                    ) {
                        var response_object = JSON.parse(error.responseText);
                        error_messages_to_display = this.extract_error_messages(
                            response_object.messages,
                        );
                    } else {
                        // Assumed to be string
                        error_messages_to_display.push(error);
                    }

                    this.display_error_output(error_messages_to_display);
                }
            },
            
            //Create custom configuration file
            create_custom_configuration_file: async function create_custom_configuration_file(
                splunk_js_sdk_service,
                properties_to_update,
            ) {
                var custom_configuration_file_name = "qualys";
                var stanza_name = "setupentity";

                await this.update_configuration_file(
                    splunk_js_sdk_service,
                    custom_configuration_file_name,
                    stanza_name,
                    properties_to_update,
                );
            },
            
            //Encrypt qualys password
            encrypt_qualys_password: async function encrypt_qualys_password(
                splunk_js_sdk_service,
                ta_username, 
                ta_password,
                app_name,
            ) {
                // /servicesNS/<NAMESPACE_USERNAME>/<SPLUNK_APP_NAME>/storage/passwords/<REALM>%3A<USERNAME>%3A
                var realm = "TA-QualysCloudPlatform-Api";
                var username = ta_username;

                var storage_passwords_accessor = splunk_js_sdk_service.storagePasswords(
                    {
                        // No namespace information provided
                    },
                );
                await storage_passwords_accessor.fetch();

                var does_storage_password_exist = this.does_storage_password_exist(
                    storage_passwords_accessor,
                    realm,
                    ta_username,
                    app_name,
                );

                if (does_storage_password_exist) {
                    await this.delete_storage_password(
                        storage_passwords_accessor,
                        realm,
                        username,
                    );
                } else {
                    // Fetch the old Qualys username from storage password if new username is different.
                    var qls_username = this.does_qualys_password_realm_exist(
                        storage_passwords_accessor,
                        realm,
                        app_name,
                    );
                    
                    qls_username = this.sanitize_string(qls_username);
                    
                    if (qls_username != "") {
                        await this.delete_storage_password(
                            storage_passwords_accessor,
                            realm,
                            qls_username,
                        );
                    }   
                }
                await storage_passwords_accessor.fetch();

                await this.create_storage_password_stanza(
                    storage_passwords_accessor,
                    realm,
                    username,
                    ta_password,
                );
            },
            
            // Encrypt CA passphrase and store it in password.conf file
            encrypt_ca_pass: async function encrypt_ca_pass(
                splunk_js_sdk_service,
                ca_pass,
                app_name,                
            ) {
                // /servicesNS/<NAMESPACE_USERNAME>/<SPLUNK_APP_NAME>/storage/passwords/<REALM>%3A<USERNAME>%3A
                var realm = "TA-QualysCloudPlatform";
                var username = "qualys_ca_passphrase";
                
                var storage_passwords_accessor = splunk_js_sdk_service.storagePasswords(
                    {
                        // No namespace information provided
                    },
                );
                await storage_passwords_accessor.fetch();

                var does_storage_password_exist = this.does_storage_password_exist(
                    storage_passwords_accessor,
                    realm,
                    username,
                    app_name,                    
                );
                
                if (does_storage_password_exist) {
                    await this.delete_storage_password(
                        storage_passwords_accessor,
                        realm,
                        username,
                    );
                }
                await storage_passwords_accessor.fetch();
                
                await this.create_storage_password_stanza(
                    storage_passwords_accessor,
                    realm,
                    username,
                    ca_pass,
                );
            },
            
            // Encrypt proxy server password and store it in password.conf file
            encrypt_proxy_server_password: async function encrypt_proxy_server_password(
                splunk_js_sdk_service,
                proxy_password,
                app_name,
            ) {
                // /servicesNS/<NAMESPACE_USERNAME>/<SPLUNK_APP_NAME>/storage/passwords/<REALM>%3A<USERNAME>%3A
                var realm = "TA-QualysCloudPlatform-Proxy";
                var username = "qualys_proxypass";
                
                var storage_passwords_accessor = splunk_js_sdk_service.storagePasswords(
                    {
                        // No namespace information provided
                    },
                );
                await storage_passwords_accessor.fetch();

                var does_storage_password_exist = this.does_storage_password_exist(
                    storage_passwords_accessor,
                    realm,
                    username,
                    app_name,
                );
                
                if (does_storage_password_exist) {
                    await this.delete_storage_password(
                        storage_passwords_accessor,
                        realm,
                        username,
                    );
                }
                await storage_passwords_accessor.fetch();
                
                await this.create_storage_password_stanza(
                    storage_passwords_accessor,
                    realm,
                    username,
                    proxy_password,
                );
            },

            complete_setup: async function complete_setup(splunk_js_sdk_service) {
                var app_name = "TA-QualysCloudPlatform";
                var configuration_file_name = "app";
                var stanza_name = "install";
                var properties_to_update = {
                    is_configured: "true",
                };

                await this.update_configuration_file(
                    splunk_js_sdk_service,
                    configuration_file_name,
                    stanza_name,
                    properties_to_update,
                );
            },
            
            // Reload the splunk app
            reload_splunk_app: async function reload_splunk_app(
                splunk_js_sdk_service,
                app_name,
            ) {
                var splunk_js_sdk_apps = splunk_js_sdk_service.apps();
                await splunk_js_sdk_apps.fetch();

                var current_app = splunk_js_sdk_apps.item(app_name);
                current_app.reload();
            },
            
            // Refresh the TA setup page
            refresh_splunk_app_setuppage: function refresh_splunk_app_setuppage(
                app_name,
            ) {
                //Fetch the is_configured value
                var is_configured = jquery("input[name=is_configured]").val();
                is_configured = this.sanitize_string(is_configured);
                
                var redirect_url = "/app/" + app_name + "/" + app_name + "?action=edit&msg=1&is_configured="+is_configured;

                window.location.href = redirect_url;
            },
            
            //Fetch the values from configuration file (qualys.conf)
            fetch_configuration_file: async function fetch_configuration_file() {
                var setup_input_fields = ["api_server","ca_path","ca_key","api_timeout","host_fields_to_log","detection_fields_to_log","max_allowed_results_field_len","detection_params","num_threads","seed_file_path","extra_was_params","num_threads_for_was","num_threads_for_pc","pc_truncation_limit","extra_posture_params","cs_num_threads","cs_image_page_size","cs_extra_params","cs_container_num_threads","cs_container_api_page_size","cs_container_extra_params","fim_events_page_size","fim_events_extra_params","fim_ignored_events_page_size","fim_ignored_events_extra_params","fim_incidents_page_size","fim_incidents_extra_params","ioc_events_pageSize","ioc_extra_params","al_extra_params","proxy_server","extra_sem_params","sem_truncation_limit","pcrs_num_count_for_pid"];
                
                var setup_checkbox_fields = ["use_ca","log_host_summary","log_extra_host_summary","log_detections","log_host_details_in_detections","use_multi_threading","enable_full_pull","enable_seed_file_generation","log_individual_findings","log_webapp_summary","use_multi_threading_for_was","log_individual_compliance_events","log_policy_summary","pc_details","pc_extra_details","pc_multi_threading_enabled","cs_log_individual_events","cs_log_summary_events","cs_multi_threading_enabled","cs_log_individual_container_events","cs_log_container_summary_events","cs_container_multi_threading_enabled","is_index_knowledgebase","log_kb_additional_fields","use_proxy","enable_debug","preserve_api_output","log_individual_sem_detection","log_sem_asset_summary","evidenceRequired"];
                
                var app_name = "TA-QualysCloudPlatform";

                var application_name_space = {
                    owner: "nobody",
                    app: app_name,
                    sharing: "app",
                };
                
                var configuration_file_name = "qualys";
                var stanza_name = "setupentity";

                try {
                    // Create the Splunk JS SDK Service object
                    splunk_js_sdk_service = this.create_splunk_js_sdk_service(
                        splunk_js_sdk,
                        application_name_space,
                    );
 
                    // Retrieve the accessor used to get a configuration file
                    var splunk_js_sdk_service_configurations = splunk_js_sdk_service.configurations(
                        {
                            // Name space information not provided
                        },
                    );
                    await splunk_js_sdk_service_configurations.fetch();
                    
                    splunk_js_sdk_service_configurations.item("qualys", function(err, propsFile) {
                        propsFile.fetch(function(err, props) {
                        console.log(props.properties()); 
                      });
                    });                    

                    // Check for the existence of the configuration file being editect
                    var does_configuration_file_exist = this.does_configuration_file_exist(
                        splunk_js_sdk_service_configurations,
                        configuration_file_name,
                    );

                    //
                    if (does_configuration_file_exist) {
                        // Retrieves the configuration file accessor
                        var configuration_file_accessor = this.get_configuration_file(
                            splunk_js_sdk_service_configurations,
                            configuration_file_name,
                        );
                        await configuration_file_accessor.fetch();

                        // Checks to see if the stanza where the inputs will be
                        // stored exist
                        var does_stanza_exist = this.does_stanza_exist(
                            configuration_file_accessor,
                            stanza_name,
                        );

                        // If the configuration stanza doesn't exist, create it
                        if (does_stanza_exist) {                            
                            // Retrieves the configuration stanza accessor
                            var configuration_stanza_accessor = this.get_configuration_file_stanza(
                                configuration_file_accessor,
                                stanza_name,
                            );
                            await configuration_stanza_accessor.fetch();
                            
                            var was_property_found = false;

                            for (const [key, value] of Object.entries(
                                configuration_stanza_accessor.properties(),
                            )) {
                                if (setup_input_fields.includes(key)) {
                                    jquery("input[name="+key+"]").val(value);
                                } else if (setup_checkbox_fields.includes(key)) {
                                    if (value == true || value == 1) {
                                        jquery("input[name="+key+"]").prop('checked', value);
                                    }
                                }
                            }
                        }
                        
                    }
                } catch (error) {
                    // This could be better error catching.
                    // Usually, error output that is ONLY relevant to the user
                    // should be displayed. This will return output that the
                    // user does not understand, causing them to be confused.
                    var error_messages_to_display = [];
                    if (
                        error !== null &&
                        typeof error === "object" &&
                        error.hasOwnProperty("responseText")
                    ) {
                        var response_object = JSON.parse(error.responseText);
                        error_messages_to_display = this.extract_error_messages(
                            response_object.messages,
                        );
                    } else {
                        // Assumed to be string
                        error_messages_to_display.push(error);
                    }

                    this.display_error_output(error_messages_to_display);
                }
            },
            
            //Fetch the values from configuration file (app.conf)
            fetch_app_configuration_file: async function fetch_app_configuration_file() {
                var setup_input_fields = ["is_configured"];
                
                var app_name = "TA-QualysCloudPlatform";

                var application_name_space = {
                    owner: "nobody",
                    app: app_name,
                    sharing: "app",
                };
                
                var configuration_file_name = "app";
                var stanza_name = "install";

                try {
                    // Create the Splunk JS SDK Service object
                    splunk_js_sdk_service = this.create_splunk_js_sdk_service(
                        splunk_js_sdk,
                        application_name_space,
                    );
 
                    // Retrieve the accessor used to get a configuration file
                    var splunk_js_sdk_service_configurations = splunk_js_sdk_service.configurations(
                        {
                            // Name space information not provided
                        },
                    );
                    await splunk_js_sdk_service_configurations.fetch();
                    
                    splunk_js_sdk_service_configurations.item("qualys", function(err, propsFile) {
                        propsFile.fetch(function(err, props) {
                        console.log(props.properties()); 
                      });
                    });                    

                    // Check for the existence of the configuration file being editect
                    var does_configuration_file_exist = this.does_configuration_file_exist(
                        splunk_js_sdk_service_configurations,
                        configuration_file_name,
                    );

                    //
                    if (does_configuration_file_exist) {
                        // Retrieves the configuration file accessor
                        var configuration_file_accessor = this.get_configuration_file(
                            splunk_js_sdk_service_configurations,
                            configuration_file_name,
                        );
                        await configuration_file_accessor.fetch();

                        // Checks to see if the stanza where the inputs will be
                        // stored exist
                        var does_stanza_exist = this.does_stanza_exist(
                            configuration_file_accessor,
                            stanza_name,
                        );

                        // If the configuration stanza doesn't exist, create it
                        if (does_stanza_exist) {                            
                            // Retrieves the configuration stanza accessor
                            var configuration_stanza_accessor = this.get_configuration_file_stanza(
                                configuration_file_accessor,
                                stanza_name,
                            );
                            await configuration_stanza_accessor.fetch();
                            
                            var was_property_found = false;

                            for (const [key, value] of Object.entries(
                                configuration_stanza_accessor.properties(),
                            )) {
                                if (setup_input_fields.includes(key)) {
                                    jquery("input[name="+key+"]").val(value);
                                }
                            }
                        }
                        
                    }
                } catch (error) {
                    // This could be better error catching.
                    // Usually, error output that is ONLY relevant to the user
                    // should be displayed. This will return output that the
                    // user does not understand, causing them to be confused.
                    var error_messages_to_display = [];
                    if (
                        error !== null &&
                        typeof error === "object" &&
                        error.hasOwnProperty("responseText")
                    ) {
                        var response_object = JSON.parse(error.responseText);
                        error_messages_to_display = this.extract_error_messages(
                            response_object.messages,
                        );
                    } else {
                        // Assumed to be string
                        error_messages_to_display.push(error);
                    }

                    this.display_error_output(error_messages_to_display);
                }
            },


            // ----------------------------------
            // Splunk JS SDK Helpers
            // ----------------------------------
            // ---------------------
            // Process Helpers
            // ---------------------
            update_configuration_file: async function update_configuration_file(
                splunk_js_sdk_service,
                configuration_file_name,
                stanza_name,
                properties,
            ) {
                // Retrieve the accessor used to get a configuration file
                var splunk_js_sdk_service_configurations = splunk_js_sdk_service.configurations(
                    {
                        // Name space information not provided
                    },
                );
                await splunk_js_sdk_service_configurations.fetch();

                // Check for the existence of the configuration file being editect
                var does_configuration_file_exist = this.does_configuration_file_exist(
                    splunk_js_sdk_service_configurations,
                    configuration_file_name,
                );

                // If the configuration file doesn't exist, create it
                if (!does_configuration_file_exist) {
                    await this.create_configuration_file(
                        splunk_js_sdk_service_configurations,
                        configuration_file_name,
                    );
                }

                // Retrieves the configuration file accessor
                var configuration_file_accessor = this.get_configuration_file(
                    splunk_js_sdk_service_configurations,
                    configuration_file_name,
                );
                await configuration_file_accessor.fetch();

                // Checks to see if the stanza where the inputs will be
                // stored exist
                var does_stanza_exist = this.does_stanza_exist(
                    configuration_file_accessor,
                    stanza_name,
                );

                // If the configuration stanza doesn't exist, create it
                if (!does_stanza_exist) {
                    await this.create_stanza(configuration_file_accessor, stanza_name);
                }
                // Need to update the information after the creation of the stanza
                await configuration_file_accessor.fetch();

                // Retrieves the configuration stanza accessor
                var configuration_stanza_accessor = this.get_configuration_file_stanza(
                    configuration_file_accessor,
                    stanza_name,
                );
                await configuration_stanza_accessor.fetch();

                // We don't care if the stanza property does or doesn't exist
                // This is because we can use the
                // configurationStanza.update() function to create and
                // change the information of a property
                await this.update_stanza_properties(
                    configuration_stanza_accessor,
                    properties,
                );
            },

            // ---------------------
            // Existence Functions
            // ---------------------
            //Check configuration file exist or not
            does_configuration_file_exist: function does_configuration_file_exist(
                configurations_accessor,
                configuration_file_name,
            ) {
                var was_configuration_file_found = false;

                var configuration_files_found = configurations_accessor.list();
                for (var index = 0; index < configuration_files_found.length; index++) {
                    var configuration_file_name_found =
                        configuration_files_found[index].name;
                    if (configuration_file_name_found === configuration_file_name) {
                        was_configuration_file_found = true;
                    }
                }

                return was_configuration_file_found;
            },
            
            //Check stanza exists or not
            does_stanza_exist: function does_stanza_exist(
                configuration_file_accessor,
                stanza_name,
            ) {
                var was_stanza_found = false;

                var stanzas_found = configuration_file_accessor.list();
                for (var index = 0; index < stanzas_found.length; index++) {
                    var stanza_found = stanzas_found[index].name;
                    if (stanza_found === stanza_name) {
                        was_stanza_found = true;
                    }
                }

                return was_stanza_found;
            },
            
            //Check stanza property exists or not
            does_stanza_property_exist: function does_stanza_property_exist(
                configuration_stanza_accessor,
                property_name,
            ) {
                var was_property_found = false;

                for (const [key, value] of Object.entries(
                    configuration_stanza_accessor.properties(),
                )) {
                    if (key === property_name) {
                        was_property_found = true;
                    }
                }

                return was_property_found;
            },
            
            //Check storage password exists or not
            does_storage_password_exist: function does_storage_password_exist(
                storage_passwords_accessor,
                realm_name,
                username,
                app_name,
            ) {
                storage_passwords = storage_passwords_accessor.list();
                storage_passwords_found = [];
                
                storage_password_compare_name = realm_name + ":" + username + ":";

                for (var index = 0; index < storage_passwords.length; index++) {
                    storage_password = storage_passwords[index];
                    storage_password_app_name = this.sanitize_string(storage_password._acl.app);
                    storage_password_stanza_name = storage_password.name;
                    if (storage_password_compare_name === storage_password_stanza_name && storage_password_app_name == app_name) {
                        storage_passwords_found.push(storage_password);
                        break;
                    }
                }
                var does_storage_password_exist = storage_passwords_found.length > 0;

                return does_storage_password_exist;
            },
            
            // Fetch the old qualys username from storage password 
            does_qualys_password_realm_exist: function does_qualys_password_realm_exist(
                storage_passwords_accessor,
                realm_name,
                app_name,
            ) {
                storage_passwords = storage_passwords_accessor.list();
                qls_username = "";
                
                storage_password_compare_name = realm_name + ":";
                for (var index = 0; index < storage_passwords.length; index++) {
                    storage_password = storage_passwords[index];
                    storage_password_stanza_name = storage_password.name;
                    storage_password_app_name = this.sanitize_string(storage_password._acl.app);
                    if (storage_password_stanza_name.indexOf(storage_password_compare_name) == 0  && storage_password_app_name == app_name) {
                        qls_username = storage_password_stanza_name.substring(storage_password_stanza_name.indexOf(':')+1,storage_password_stanza_name.lastIndexOf(':'));
                        break;
                    }
                }
                return qls_username;
            },

            // ---------------------
            // Retrieval Functions
            // ---------------------
            //Get configuration file
            get_configuration_file: function get_configuration_file(
                configurations_accessor,
                configuration_file_name,
            ) {
                var configuration_file_accessor = configurations_accessor.item(
                    configuration_file_name,
                    {
                        // Name space information not provided
                    },
                );

                return configuration_file_accessor;
            },
            
            //Get configuration file stanza
            get_configuration_file_stanza: function get_configuration_file_stanza(
                configuration_file_accessor,
                configuration_stanza_name,
            ) {
                var configuration_stanza_accessor = configuration_file_accessor.item(
                    configuration_stanza_name,
                    {
                        // Name space information not provided
                    },
                );

                return configuration_stanza_accessor;
            },
            
            //Get configuration file stanza property
            get_configuration_file_stanza_property: function get_configuration_file_stanza_property(
                configuration_file_accessor,
                configuration_file_name,
            ) {
                return null;
            },

            // ---------------------
            // Creation Functions
            // ---------------------
            create_splunk_js_sdk_service: function create_splunk_js_sdk_service(
                splunk_js_sdk,
                application_name_space,
            ) {
                var http = new splunk_js_sdk.SplunkWebHttp();

                var splunk_js_sdk_service = new splunk_js_sdk.Service(
                    http,
                    application_name_space,
                );

                return splunk_js_sdk_service;
            },
            
            //Create configuration file
            create_configuration_file: function create_configuration_file(
                configurations_accessor,
                configuration_file_name,
            ) {
                var parent_context = this;

                return configurations_accessor.create(configuration_file_name, function(
                    error_response,
                    created_file,
                ) {
                    // Do nothing
                });
            },
            
            //Create stanza
            create_stanza: function create_stanza(
                configuration_file_accessor,
                new_stanza_name,
            ) {
                var parent_context = this;

                return configuration_file_accessor.create(new_stanza_name, function(
                    error_response,
                    created_stanza,
                ) {
                    // Do nothing
                });
            },
            
            //Update stanza properties
            update_stanza_properties: function update_stanza_properties(
                configuration_stanza_accessor,
                new_stanza_properties,
            ) {
                var parent_context = this;

                return configuration_stanza_accessor.update(
                    new_stanza_properties,
                    function(error_response, entity) {
                        // Do nothing
                    },
                );
            },

            //Create storage password stanza
            create_storage_password_stanza: function create_storage_password_stanza(
                splunk_js_sdk_service_storage_passwords,
                realm,
                username,
                value_to_encrypt,
            ) {
                var parent_context = this;

                return splunk_js_sdk_service_storage_passwords.create(
                    {
                        name: username,
                        password: value_to_encrypt,
                        realm: realm,
                    },
                    function(error_response, response) {
                        // Do nothing
                    },
                );
            },

            // ----------------------------------
            // Deletion Methods
            // ----------------------------------
            //Delete storage password
            delete_storage_password: function delete_storage_password(
                storage_passwords_accessor,
                realm,
                username,
            ) {
                return storage_passwords_accessor.del(realm + ":" + username + ":");
            },

            // ----------------------------------
            // Input Cleaning and Checking
            // ----------------------------------
            //Sanitize input value
            sanitize_string: function sanitize_string(string_to_sanitize) {
                var sanitized_string = string_to_sanitize.trim();

                return sanitized_string;
            },
            
            //Validate setup form inputs
            validate_inputs: function validate_inputs(ta_username, ta_password, ta_confirm_password, ca_pass, ca_pass_confirm, properties_to_update) {
                var error_messages = [];

                var api_server_errors = this.validate_api_server_input(properties_to_update['api_server']);
                var username_password_errors = this.validate_username_password_input(ta_username, ta_password);
                var password_errors = this.validate_password_input(ta_password, ta_confirm_password);
                var ca_password_errors = this.validate_ca_password_input(ca_pass, ca_pass_confirm);
                var detection_params_errors = this.validate_detection_params_input(properties_to_update['detection_params']);
                var extra_was_params_errors = this.validate_extra_was_params_input(properties_to_update['extra_was_params']);
                var extra_posture_params_errors = this.validate_extra_posture_params_input(properties_to_update['extra_posture_params']);
                var max_allowed_results_field_len_errors = this.validate_max_allowed_results_field_len_input(properties_to_update['max_allowed_results_field_len']);
                var num_threads_errors = this.validate_num_threads_input(properties_to_update['num_threads']);
                var num_threads_for_was_errors = this.validate_num_threads_for_was_input(properties_to_update['num_threads_for_was']);
                var num_threads_for_pc_errors = this.validate_num_threads_for_pc_input(properties_to_update['num_threads_for_pc']);
                var cs_num_threads_errors = this.validate_cs_num_threads_input(properties_to_update['cs_num_threads']);
                var cs_container_num_threads_errors = this.validate_cs_container_num_threads_input(properties_to_update['cs_container_num_threads']);
                var api_timeout_errors = this.validate_api_timeout_input(properties_to_update['api_timeout']);
                var proxy_configuration_errors = this.validate_proxy_configuration_input(properties_to_update['use_proxy'], properties_to_update['proxy_server']);
                var proxy_server_errors = this.validate_proxy_server_input(properties_to_update['proxy_server']);
                var al_extra_params_errors = this.validate_al_extra_params_input(properties_to_update['al_extra_params']);
                var fim_events_page_size_errors = this.validate_fim_events_page_size_input(properties_to_update['fim_events_page_size']);
                var fim_ignored_events_page_size_errors = this.validate_fim_ignored_events_page_size_input(properties_to_update['fim_ignored_events_page_size']);
                var fim_incidents_page_size_errors = this.validate_fim_incidents_page_size_input(properties_to_update['fim_incidents_page_size']);
                var ioc_events_pageSize_errors = this.validate_ioc_events_pageSize_input(properties_to_update['ioc_events_pageSize']);
                var cs_image_page_size_errors = this.validate_cs_image_page_size_input(properties_to_update['cs_image_page_size']);
                var cs_container_api_page_size_errors = this.validate_cs_container_api_page_size_input(properties_to_update['cs_container_api_page_size']);
                var pc_truncation_limit_errors = this.validate_pc_truncation_limit_input(properties_to_update['pc_truncation_limit']);
                var extra_sem_params_errors = this.validate_sem_extra_params_input(properties_to_update['extra_sem_params']);
                var sem_truncation_limit_errors = this.validate_sem_truncation_limit_input(properties_to_update['sem_truncation_limit']);
                var pcrs_num_count_for_pid_errors = this.validate_pcrs_num_count_for_pid_input(properties_to_update['pcrs_num_count_for_pid']);                

                error_messages = error_messages.concat(api_server_errors);
                error_messages = error_messages.concat(username_password_errors);
                error_messages = error_messages.concat(password_errors);
                error_messages = error_messages.concat(ca_password_errors);
                error_messages = error_messages.concat(detection_params_errors);
                error_messages = error_messages.concat(extra_was_params_errors);
                error_messages = error_messages.concat(extra_posture_params_errors);
                error_messages = error_messages.concat(max_allowed_results_field_len_errors);
                error_messages = error_messages.concat(num_threads_errors);
                error_messages = error_messages.concat(num_threads_for_was_errors);
                error_messages = error_messages.concat(num_threads_for_pc_errors);
                error_messages = error_messages.concat(cs_num_threads_errors);
                error_messages = error_messages.concat(cs_container_num_threads_errors);
                error_messages = error_messages.concat(api_timeout_errors);
                error_messages = error_messages.concat(proxy_configuration_errors);
                error_messages = error_messages.concat(proxy_server_errors);
                error_messages = error_messages.concat(al_extra_params_errors);
                error_messages = error_messages.concat(fim_events_page_size_errors);
                error_messages = error_messages.concat(fim_ignored_events_page_size_errors);
                error_messages = error_messages.concat(fim_incidents_page_size_errors);
                error_messages = error_messages.concat(ioc_events_pageSize_errors);
                error_messages = error_messages.concat(cs_image_page_size_errors);
                error_messages = error_messages.concat(cs_container_api_page_size_errors);
                error_messages = error_messages.concat(pc_truncation_limit_errors);
                error_messages = error_messages.concat(extra_sem_params_errors);
                error_messages = error_messages.concat(sem_truncation_limit_errors); 
                error_messages = error_messages.concat(pcrs_num_count_for_pid_errors);                               

                return error_messages;
            },

            // Validate API server URL
            validate_api_server_input: function validate_api_server_input(api_server) {
                var error_messages = [];
                
                var is_api_server_empty = typeof api_server === "undefined" || api_server === "";
                
                if (is_api_server_empty === true) {
                    error_message = "Please provide the valid URI for Qualys API Server.";
                    error_messages.push(error_message);
                } else {
                    var pattern = /^http(s)?\:\/\/((([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])(\:(6553[0-5]|655[0-2][0-9]\d|65[0-4](\d){2}|6[0-4](\d){3}|[1-5](\d){4}|[1-9](\d){0,3}))?)|(((\w+\.)+.\w+(\:(6553[0-5]|655[0-2][0-9]\d|65[0-4](\d){2}|6[0-4](\d){3}|[1-5](\d){4}|[1-9](\d){0,3}))?)))$/i;
                    
                    if (!pattern.test(api_server)) {
                        error_message = "Please provide the valid URI for Qualys API Server.";
                        error_messages.push(error_message);
                    }
                }

                return error_messages;
            },

            // Validate proxy server configuration
            validate_proxy_configuration_input: function validate_proxy_configuration_input(use_proxy, proxy_server) {
                var error_messages = [];

                var is_use_proxy = $("#use_proxy").is(':checked');
                var is_proxy_server_empty = typeof proxy_server === "undefined" || proxy_server === "";

                if (is_use_proxy === true && is_proxy_server_empty === true) {
                    error_message = "Please enter proxy server and credentials.";
                    error_messages.push(error_message);
                } else if (is_use_proxy === false && is_proxy_server_empty === false) {
                    error_message = "Please check the 'use a proxy server for Qualys API requests' option.";
                    error_messages.push(error_message);
                }

                return error_messages;
            },

            // Validate proxy server
            validate_proxy_server_input: function validate_proxy_server_input(proxy_server) {
                var error_messages = [];

                var is_proxy_server_empty = typeof proxy_server === "undefined" || proxy_server === "";
                if (is_proxy_server_empty === false) {
                    var pattern = /^(?:([a-zA-Z0-9_.]+)(?::)+([a-zA-Z0-9_*!@#$%^&]+)@)?(?:https?:\/\/)?(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|(?![\d.]+:)\w+(?:\.\w+)*:\d+\S+|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?::(?![7-9]\d\d\d\d)(?!6[6-9]\d\d\d)(?!65[6-9]\d\d)(?!655[4-9]\d)(?!6553[6-9])(?!0+)([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?(?:\/?|[\/?]\S+)$/i;
                    
                    if (!pattern.test(proxy_server)) {
                        error_message = "Please provide the valid URI for proxy server.";
                        error_messages.push(error_message);
                    }
                }

                return error_messages;
            },

            // Validate username and password while update
            validate_username_password_input: function validate_username_password_input(ta_username, ta_password) {
                var error_messages = [];

                var is_ta_password_empty = typeof ta_password === "undefined" || ta_password === "";
                var is_ta_username_empty = typeof ta_username === "undefined" || ta_username === "";
                
                if (is_ta_password_empty === false && is_ta_username_empty === true) {
                    error_message = "Please provide the username.";
                    error_messages.push(error_message);
                } else if (is_ta_password_empty === true && is_ta_username_empty === false) {
                    error_message = "Please provide the password.";
                    error_messages.push(error_message);
                }

                return error_messages;
            },

            // Validate Qualys API password and confirm password are same or not
            validate_password_input: function validate_password_input(ta_password, ta_confirm_password) {
                var error_messages = [];

                var is_ta_password_empty = typeof ta_password === "undefined" || ta_password === "";
                var is_ta_confirm_password_empty = typeof ta_confirm_password === "undefined" || ta_confirm_password === "";
                
                if (is_ta_password_empty === false || is_ta_confirm_password_empty === false) {
                    if (ta_password !== ta_confirm_password) {
                        error_message = "Password and confirm password do not match.";
                        error_messages.push(error_message);
                    }
                }

                return error_messages;
            },

            // Validate Passphrase for client CA certificate
            validate_ca_password_input: function validate_ca_password_input(ca_pass, ca_pass_confirm) {
                var error_messages = [];
                
                var is_ca_pass_empty = typeof ca_pass === "undefined" || ca_pass === "";
                var is_ca_pass_confirm_empty = typeof ca_pass_confirm === "undefined" || ca_pass_confirm === "";
                
                if (is_ca_pass_empty === false || is_ca_pass_confirm_empty === false) {
                    if (ca_pass !== ca_pass_confirm) {
                        error_message = "Client certificate passphrase and confirm passphrase do not match.";
                        error_messages.push(error_message);
                    }
                }

                return error_messages;
            },

            // Validate whether detection param is either in JSON or query string
            validate_detection_params_input: function validate_detection_params_input(detection_params) {
                var error_messages = [];

                var is_detection_params_empty = typeof detection_params === "undefined" || detection_params === "";
 
                if (is_detection_params_empty == false) {
                    is_query_str = this.is_query_str(detection_params);
                    is_json_str = this.is_json_str(detection_params);

                    if (is_query_str == false && is_json_str == false) {
                        error_message = "Host Detection extra parameters should be either JSON or Query String.";
                        error_messages.push(error_message);
                    }
                }

                return error_messages;
            },

            // Validate whether extra WAS params is XML format
            validate_extra_was_params_input: function validate_extra_was_params_input(extra_was_params) {
                var error_messages = [];
                
                var is_extra_was_params_empty = typeof extra_was_params === "undefined" || extra_was_params === "";
                
                if (is_extra_was_params_empty == false) {
                    
                    if (this.is_xml_str(extra_was_params) == false) {
                        error_message = "WAS Findings extra parameters should be XML.";
                        error_messages.push(error_message);
                    }
                }

                return error_messages;
            },

            // Validate whether detection param is in either JSON or query string format
            validate_extra_posture_params_input: function validate_extra_posture_params_input(extra_posture_params) {
                var error_messages = [];
                var is_extra_posture_params_empty = typeof extra_posture_params === "undefined" || extra_posture_params === "";
                
                if (is_extra_posture_params_empty == false) {
                    is_query_str = this.is_query_str(extra_posture_params);
                    is_json_str = this.is_json_str(extra_posture_params);
                    
                    if (is_query_str == false && is_json_str == false) {
                        error_message = "Policy Compliance extra parameters should be either JSON or Query String.";
                        error_messages.push(error_message);
                    }
                }
                
                return error_messages;
            },

            // Validate max allowed results field length for Host Detection
            validate_max_allowed_results_field_len_input: function validate_max_allowed_results_field_len_input(max_allowed_results_field_len) {
                var error_messages = [];
                var is_max_allowed_results_field_len_empty = typeof max_allowed_results_field_len === "undefined" || max_allowed_results_field_len === "";
                
                if (is_max_allowed_results_field_len_empty == false) {
                    var is_number = this.is_number(max_allowed_results_field_len);
                    if (is_number == false) {
                        error_message = "Max characters allowed in the RESULTS field should be a positive number.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Max characters allowed in the RESULTS field should be a positive number.";
                    error_messages.push(error_message);
                }

                return error_messages;
            },

            // Validate Number of threads for Host Detection
            validate_num_threads_input: function validate_num_threads_input(num_threads) {
                var error_messages = [];
                var is_num_threads_empty = typeof num_threads === "undefined" || num_threads === "";
                
                if (is_num_threads_empty == false) {
                    var is_number = this.is_number(num_threads);
                    if (is_number == false) {
                        error_message = "Number of threads for Host Detection input should be between 1 to 10.";
                        error_messages.push(error_message);
                    } else if (num_threads < 1 || num_threads > 10) {
                        error_message = "Number of threads for Host Detection input should be between 1 to 10.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Number of threads for Host Detection input should be between 1 to 10.";
                    error_messages.push(error_message);
                }

                return error_messages;
            },
            
            //Validate Number of threads for WAS
            validate_num_threads_for_was_input: function validate_num_threads_for_was_input(num_threads_for_was) {
                var error_messages = [];
                var is_num_threads_for_was_empty = typeof num_threads_for_was === "undefined" || num_threads_for_was === "";
                
                if (is_num_threads_for_was_empty == false) {
                    var is_number = this.is_number(num_threads_for_was);
                    if (is_number == false) {
                        error_message = "Number of threads for WAS Findings input should be between 1 to 10.";
                        error_messages.push(error_message);
                    } else if (num_threads_for_was < 1 || num_threads_for_was > 10) {
                        error_message = "Number of threads for WAS Findings input should be between 1 to 10.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Number of threads for WAS Findings input should be between 1 to 10.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },

            //Validate Number of threads for PC
            validate_num_threads_for_pc_input: function validate_num_threads_for_pc_input(num_threads_for_pc) {
                var error_messages = [];
                var is_num_threads_for_pc_empty = typeof num_threads_for_pc === "undefined" || num_threads_for_pc === "";
                
                if (is_num_threads_for_pc_empty == false) {
                    var is_number = this.is_number(num_threads_for_pc);
                    if (is_number == false) {
                        error_message = "Number of threads for Policy Compliance input should be between 1 to 10.";
                        error_messages.push(error_message);
                    } else if (num_threads_for_pc < 1 || num_threads_for_pc > 10) {
                        error_message = "Number of threads for Policy Compliance input should be between 1 to 10.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Number of threads for Policy Compliance input should be between 1 to 10.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },

            //Validate CS image num threads
            validate_cs_num_threads_input: function validate_cs_num_threads_input(cs_num_threads) {
                var error_messages = [];
                var is_cs_num_threads_empty = typeof cs_num_threads === "undefined" || cs_num_threads === "";
                
                if (is_cs_num_threads_empty == false) {
                    var is_number = this.is_number(cs_num_threads);
                    if (is_number == false) {
                        error_message = "Number of threads for Container Security Images input should be between 1 to 10.";
                        error_messages.push(error_message);
                    } else if (cs_num_threads < 1 || cs_num_threads > 10) {
                        error_message = "Number of threads for Container Security Images input should be between 1 to 10.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Number of threads for Container Security Images input should be between 1 to 10.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },

            //Validate CS container num threads
            validate_cs_container_num_threads_input: function validate_cs_container_num_threads_input(cs_container_num_threads) {
                var error_messages = [];
                var is_cs_container_num_threads_empty = typeof cs_container_num_threads === "undefined" || cs_container_num_threads === "";
                
                if (is_cs_container_num_threads_empty == false) {
                    var is_number = this.is_number(cs_container_num_threads);
                    if (is_number == false) {
                        error_message = "Number of threads for Container Security Containers input should be between 1 to 10.";
                        error_messages.push(error_message);
                    } else if (cs_container_num_threads < 1 || cs_container_num_threads > 10) {
                        error_message = "Number of threads for Container Security Containers input should be between 1 to 10.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Number of threads for Container Security Containers input should be between 1 to 10.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },
            
            //Validate API timeout
            validate_api_timeout_input: function validate_api_timeout_input(api_timeout) {
                var error_messages = [];
                var is_api_timeout_empty = typeof api_timeout === "undefined" || api_timeout === "";
                
                if (is_api_timeout_empty == false) {
                    var is_number = this.is_number(api_timeout);
                    if (is_number == false) {
                        error_message = "API timeout should be positive number.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "API timeout should be positive number.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },
            
            //Validate fim events page size
            validate_fim_events_page_size_input: function validate_fim_events_page_size_input(fim_events_page_size) {
                var error_messages = [];
                var is_fim_events_page_size_empty = typeof fim_events_page_size === "undefined" || fim_events_page_size === "";
                
                if (is_fim_events_page_size_empty == false) {
                    var is_number = this.is_number(fim_events_page_size);
                    
                    if (is_number == false) {
                        error_message = "Fim events page size should be positive number.";
                        error_messages.push(error_message);
                    } else if (fim_events_page_size < 1) {
                        error_message = "Fim events page size should be greater than 0.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Fim events page size should be greater than 0.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },
            
            //Validate fim ignored events page size
            validate_fim_ignored_events_page_size_input: function validate_fim_ignored_events_page_size_input(fim_ignored_events_page_size) {
                var error_messages = [];
                var is_fim_ignored_events_page_size_empty = typeof fim_ignored_events_page_size === "undefined" || fim_ignored_events_page_size === "";
                
                if (is_fim_ignored_events_page_size_empty == false) {
                    var is_number = this.is_number(fim_ignored_events_page_size);
                    
                    if (is_number == false) {
                        error_message = "Fim ignored events page size should be positive number.";
                        error_messages.push(error_message);
                    } else if (fim_ignored_events_page_size < 1) {
                        error_message = "Fim ignored events page size should be greater than 0.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Fim ignored events page size should be greater than 0.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },
            
            //Validate fim incidents page size
            validate_fim_incidents_page_size_input: function validate_fim_incidents_page_size_input(fim_incidents_page_size) {
                var error_messages = [];
                var is_fim_incidents_page_size_empty = typeof fim_incidents_page_size === "undefined" || fim_incidents_page_size === "";
                
                if (is_fim_incidents_page_size_empty == false) {
                    var is_number = this.is_number(fim_incidents_page_size);
                    
                    if (is_number == false) {
                        error_message = "Fim incidents page size should be positive number.";
                        error_messages.push(error_message);
                    } else if (fim_incidents_page_size < 1) {
                        error_message = "Fim incidents page size should be greater than 0.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Fim incidents page size should be greater than 0.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },
            
            //Validate ioc events pageSize
            validate_ioc_events_pageSize_input: function validate_ioc_events_pageSize_input(ioc_events_pageSize) {
                var error_messages = [];
                var is_ioc_events_pageSize_empty = typeof ioc_events_pageSize === "undefined" || ioc_events_pageSize === "";
                
                if (is_ioc_events_pageSize_empty == false) {
                    var is_number = this.is_number(ioc_events_pageSize);
                    
                    if (is_number == false) {
                        error_message = "Endpoint Detection and Response page size should be positive number.";
                        error_messages.push(error_message);
                    } else if (ioc_events_pageSize < 1) {
                        error_message = "Endpoint Detection and Response page size should be greater than 0.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Endpoint Detection and Response page size should be greater than 0.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },
            
            //Validate cs image page size
            validate_cs_image_page_size_input: function validate_cs_image_page_size_input(cs_image_page_size) {
                var error_messages = [];
                var is_cs_image_page_size_empty = typeof cs_image_page_size === "undefined" || cs_image_page_size === "";
                
                if (is_cs_image_page_size_empty == false) {
                    var is_number = this.is_number(cs_image_page_size);
                    
                    if (is_number == false) {
                        error_message = "CS image page size should be positive number.";
                        error_messages.push(error_message);
                    } else if (cs_image_page_size < 1) {
                        error_message = "CS image page size should be greater than 0.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "CS image page size should be greater than 0.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },
            
            //Validate cs container api page size
            validate_cs_container_api_page_size_input: function validate_cs_image_page_size_input(cs_container_api_page_size) {
                var error_messages = [];
                var is_cs_container_api_page_size_empty = typeof cs_container_api_page_size === "undefined" || cs_container_api_page_size === "";
                
                if (is_cs_container_api_page_size_empty == false) {
                    var is_number = this.is_number(cs_container_api_page_size);
                    
                    if (is_number == false) {
                        error_message = "CS container api page size should be positive number.";
                        error_messages.push(error_message);
                    } else if (cs_container_api_page_size < 1) {
                        error_message = "CS container api page size should be greater than 0.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "CS container api page size should be greater than 0.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },

            //Validate PC truncation limit
            validate_pc_truncation_limit_input: function validate_pc_truncation_limit_input(pc_truncation_limit) {
                var error_messages = [];
                var is_pc_truncation_limit_empty = typeof pc_truncation_limit === "undefined" || pc_truncation_limit === "";
                
                if (is_pc_truncation_limit_empty == false) {
                    var is_number = this.is_number(pc_truncation_limit);
                    
                    if (is_number == false) {
                        error_message = "Number of posture info records per API request should be equal/greater than 0.";
                        error_messages.push(error_message);
                    } else if (pc_truncation_limit < 0) {
                        error_message = "Number of posture info records per API request should be equal/greater than 0.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Number of posture info records per API request should be equal/greater than 0.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },

            // Validate whether Activity Log param is either in JSON or query string
            validate_al_extra_params_input: function validate_al_extra_params_input(al_extra_param) {
                var error_messages = [];
                var is_al_extra_param_empty = typeof al_extra_param === "undefined" || al_extra_param === "";
                if (is_al_extra_param_empty == false) {
                    is_query_str = this.is_query_str(al_extra_param);
                    is_json_str = this.is_json_str(al_extra_param);
                    
                    if (is_query_str == false && is_json_str == false) {
                        error_message = "Activity Log extra parameters should be either JSON or Query String.";
                        error_messages.push(error_message);
                    }
                }

                return error_messages;
            },

            // Validate whether SEM extra param is in query string
            validate_sem_extra_params_input: function validate_sem_extra_params_input(extra_sem_params) {
                var error_messages = [];

                var is_extra_sem_params_empty = typeof extra_sem_params === "undefined" || extra_sem_params === "";
 
                if (is_extra_sem_params_empty == false) {
                    is_query_str = this.is_query_str(extra_sem_params);

                    if (is_query_str == false) {
                        error_message = "Secure Enterprise Mobility extra parameters should be query string.";
                        error_messages.push(error_message);
                    }
                }

                return error_messages;
            },
            
            //Validate SEM truncation limit
            validate_sem_truncation_limit_input: function validate_sem_truncation_limit_input(sem_truncation_limit) {
                var error_messages = [];
                var is_sem_truncation_limit_empty = typeof sem_truncation_limit === "undefined" || sem_truncation_limit === "";
                
                if (is_sem_truncation_limit_empty == false) {
                    var is_number = this.is_number(sem_truncation_limit);
                    
                    if (is_number == false) {
                        error_message = "Number of SEM records per API request should be equal/greater than 0.";
                        error_messages.push(error_message);
                    } else if (sem_truncation_limit < 1) {
                        error_message = "Number of SEM records per API request should be equal/greater than 0.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Number of SEM records per API request should be equal/greater than 0.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },

            //Validate Number of Policy IDs per resolve host ids api call for PCRS
            validate_pcrs_num_count_for_pid_input: function validate_pcrs_num_count_for_pid_input(pcrs_num_count_for_pid) {
                var error_messages = [];
                var is_pcrs_num_count_for_pid_empty = typeof pcrs_num_count_for_pid === "undefined" || pcrs_num_count_for_pid === "";
                
                if (is_pcrs_num_count_for_pid_empty == false) {
                    var is_number = this.is_number(pcrs_num_count_for_pid);
                    if (is_number == false) {
                        error_message = "Number of Policy Ids per API call for Policy Compliance Reporitng Service input should be between 1 to 10.";
                        error_messages.push(error_message);
                    } else if (pcrs_num_count_for_pid < 1 || pcrs_num_count_for_pid > 10) {
                        error_message = "Number of Policy Ids per API call for Policy Compliance Reporitng Service input should be between 1 to 10.";
                        error_messages.push(error_message);
                    }
                } else {
                    error_message = "Number of Policy Ids per API call for Policy Compliance Reporitng Service input should be between 1 to 10.";
                    error_messages.push(error_message);
                }

                return error_messages;                
            },            

            
            // Validate whether input value is in JSON format or not 
            is_json_str: function is_json_str(input_str) {
                try {
                    JSON.parse(input_str);
                } catch (e) {
                    return false;
                }
                return true;
            },

            // Validate whether input value is query string or not 
            is_query_str: function is_query_str(input_str) {
                var pattern = /^([\w"']+=([\w|\W])+)?$/i;
                
                if(!pattern.test(input_str)) {
                    return false;
                } else {
                    return true;
                }
            },

            // Validate whether input string is in XML format or not 
            is_xml_str: function is_xml_str(input_str) {
                try {
                    $.parseXML(input_str);
                } catch (e) {
                    return false;
                }
                return true;
            },

            // Validate whether input value is number or not 
            is_number: function is_number(input_str) {
                var pattern = /^[0-9]+$/;
                
                if (pattern.test(input_str)) {
                    return true;
                } else {
                    return false;
                }
            },

            // Fetch proxy password from proxy server
            fetch_proxy_password: function fetch_proxy_password(proxy_server) {
                var search_term = ":****@";
                var str1 = proxy_server;
                
                if (proxy_server.indexOf(search_term) == -1) {
                    var pattern = /(?:https?:\/\/)?(\w+:)(.*)(?=@)/i;
                    
                    if (pattern.test(proxy_server)) {
                        group_regex = /(?<=:)(.*)(?=@)/;
                        var result = group_regex.exec(proxy_server);
                        
                        return result[0];
                    } else {
                        return "";
                    }
                } else {
                    return "";
                }
            },
            
            // ----------------------------------
            // GUI Helpers
            // ----------------------------------
            extract_error_messages: function extract_error_messages(error_messages) {
                // A helper function to extract error messages

                // Expects an array of messages
                // [
                //     {
                //         type: the_specific_error_type_found,
                //         text: the_specific_reason_for_the_error,
                //     },
                //     ...
                // ]

                var error_messages_to_display = [];
                for (var index = 0; index < error_messages.length; index++) {
                    error_message = error_messages[index];
                    error_message_to_display =
                        error_message.type + ": " + error_message.text;
                    error_messages_to_display.push(error_message_to_display);
                }

                return error_messages_to_display;
            },

            // ----------------------------------
            // Display Functions
            // ----------------------------------
            // Display error messages
            display_error_output: function display_error_output(error_messages) {
                // Hides the element if no messages, shows if any messages exist
                var did_error_messages_occur = error_messages.length > 0;

                var error_output_element = jquery(".container .error.output");

                if (did_error_messages_occur) {
                    var new_error_output_string = "";
                    new_error_output_string += "<ul>";
                    for (var index = 0; index < error_messages.length; index++) {
                        new_error_output_string +=
                            "<li>" + error_messages[index] + "</li>";
                    }
                    new_error_output_string += "</ul>";

                    error_output_element.html(new_error_output_string);
                    error_output_element.stop();
                    error_output_element.fadeIn();
                    error_output_element.focus();
                } else {
                    error_output_element.stop();
                    error_output_element.fadeOut({
                        complete: function() {
                            error_output_element.html("");
                        },
                    });
                }
            },

            //Get HTML template
            get_template: function get_template() {
                template_string =
                                "<div class='container'>" +
                                "    <div id='success_output' class='success_output' tabindex='1'>" +
                                "    Successfully saved the settings." +
                                "    </div>" +
                                "    <div id='info_output' class='info_output' tabindex='1'>" +
                                "    Please restart the Splunk to take new settings into effect." +
                                "    </div>" +
                                "    <div class='title'>" +
                                "        <h1>Configure This App</h1>" +
                                "    </div>" +
                                "    <div id='error_output' class='error output' tabindex='1'>" +
                                "    </div>" +
                                "    <div class='row'>" +
                                "        <h3>Qualys API Server</h3>" +
                                "        <div class='col-25'>" +
                                "            <label>Qualys API Server</label>" +
                                "        </div>" +
                                "        <div class='col-75'>" +
                                "            <input type='text' id='api_server' name='api_server' >" +
                                "        </div>" +
                                "    </div>" +
                                "    <div class='row'>" +
                                "        <i><b>Note:</b> The url should start with HTTPS.</i>" +
                                "    </div>" +
                                "    <div class='row'>" +
                                "        <h3>Qualys Credentials</h3>" +
                                "        <div class='col-25'>" +
                                "            <label>Username</label>" +
                                "        </div>" +
                                "        <div class='col-75'>" +
                                "            <input type='text' id='name' name='name' >" +
                                "        </div>" +
                                "    </div>" +
                                "    <div class='row'>" +
                                "        <div class='col-25'>" +
                                "            <label>Password</label>" +
                                "        </div>" +
                                "        <div class='col-75'>" +
                                "            <input type='password' id='password' name='password' >" +
                                "        </div>" +
                                "    </div>" +
                                "    <div class='row'>" +
                                "        <div class='col-25'>" +
                                "            <label>Confirm Password</label>" +
                                "        </div>" +
                                "        <div class='col-75'>" +
                                "            <input type='password' id='confirm_password' name='confirm_password' >" +
                                "        </div>" +
                                "    </div>" +
                                "    <div class='row_note'>" +
                                "        <i><b>Note:</b> Leave username/password blank, if you have already set it up.</i><br>" +
                                "    </div>" +                                                                 
                                                                
                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd2' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd2'>Client Certificate</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='use_ca' name='use_ca' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Use a Client certificate for authentication</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Path to client CA certificate</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='ca_path' name='ca_path' >" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Path to client CA certificate key</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='ca_key' name='ca_key' >" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Passphrase for client CA certificate</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='password' id='ca_pass' name='ca_pass' >" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Confirm Passphrase</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='password' id='ca_pass_confirm' name='ca_pass_confirm' >" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>"+                                
                                                    
                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd3' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd3'>API Timeout Settings</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>API request timeout period in seconds</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='api_timeout' name='api_timeout' >" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +
                               
                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd4' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd4'>VM Detection Settings</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_host_summary' name='log_host_summary' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log Host Summary events</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_extra_host_summary' name='log_extra_host_summary' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log extra statistics in host summary ( Breakdown of Vulnerability Count by (Severity and Type), by (Severity and Status)</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_detections' name='log_detections' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log Individual Host Vulnerabilities</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_host_details_in_detections' name='log_host_details_in_detections' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log host information with each detection ( e.g. IP, OS, DNS, NetBios)</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Host fields to log</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='host_fields_to_log' name='host_fields_to_log' >Enter host XML tag names from API response to be logged in the event by a comma-separated. (e.g. ID,IP,TRACKING_METHOD,DNS)" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Detection fields to log</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='detection_fields_to_log' name='detection_fields_to_log' >Enter detection XML tag names from API response to be logged in the event by a comma-separated. (e.g. QID,TYPE,PORT,PROTOCOL)" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Max characters allowed in RESULTS field</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='max_allowed_results_field_len' name='max_allowed_results_field_len' >Value 0 means TA won't truncate the RESULTS field. Non zero value means TA will truncate the RESULTS field at that length." +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra parameters for Detection API</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='detection_params' name='detection_params' >" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           Enter as URL Query (e.g. a=1&amp;b=string ) or as JSON (e.g. {\"a\":1, \"b\": \"string\"} ). Following parameters are NOT allowed:action, output_format, vm_processed_after, ids, suppress_duplicated_data_from_csv, max_days_since_last_vm_scan, max_days_since_vm_scan" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='use_multi_threading' name='use_multi_threading' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Load detection data using multiple threads (resource intensive)</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Number of threads to use (between 1 and 10)</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='num_threads' name='num_threads' >" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <h3>VM Detection - Advanced Settings</h3>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='enable_full_pull' name='enable_full_pull' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Enable full data pull always? If checked, TA will always do a full data pull. Leave unchecked for incremental pull.</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='enable_seed_file_generation' name='enable_seed_file_generation' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Enable .seed file generation? If checked, TA will only generate a .seed file instead of streaming data. You will have to explicitly import it later. Leave unchecked to let TA stream data into Splunk.</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Directory path, where to generate the .seed file.</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='seed_file_path' name='seed_file_path' >" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd5' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd5'>WAS Findings Settings</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_individual_findings' name='log_individual_findings' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log Individual Findings</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_webapp_summary' name='log_webapp_summary' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log Web App Summary events</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra parameters to WAS Findings API</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='extra_was_params' name='extra_was_params' />Enter as XML. (e.g. &lt;filters&gt;&lt;Criteria field=\"group\" operator=\"IN\"&gt;XSS, SQL, INFO&lt;/Criteria&gt;&lt;/filters&gt;)" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='use_multi_threading_for_was' name='use_multi_threading_for_was' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Load WAS Findings data using multiple threads (resource intensive)</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Number of threads to use (between 1 and 10)</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='num_threads_for_was' name='num_threads_for_was' >" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd6' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd6'>Policy Compliance Settings</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <i><b>Note:</b> The PC feed does not pull the SCAP information.</i>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_individual_compliance_events' name='log_individual_compliance_events' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log individual PC Compliance Posture events</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_policy_summary' name='log_policy_summary' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log Policy Summary</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='pc_details' name='pc_details' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log \"All\" details (when unchecked, logs \"Basic\" details)</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='pc_extra_details' name='pc_extra_details' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Add additional fields (REMEDIATION, RATIONALE, EVIDENCE, CAUSE_OF_FAILURE)</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='pc_multi_threading_enabled' name='pc_multi_threading_enabled' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Enable multi-threading for PC Posture Information download</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Number of threads to use for PC Posture Information (max 10)</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='num_threads_for_pc' name='num_threads_for_pc' >" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Number of posture info records per API request</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='pc_truncation_limit' name='pc_truncation_limit' >" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra parameters for Posture Information API</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='extra_posture_params' name='extra_posture_params' /><b>Note</b> Enter as URL Query (e.g. a=1&amp;b=string) or as JSON (e.g. {\"a\":1, \"b\": \"string\"}). Following parameters are NOT allowed: action, output_format, details, status_changes_since, policy_ids, show_remediation_info, cause_of_failure, include_dp_name, policy_id, truncation_limit" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd7' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd7'>Container Security Settings for Images</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='cs_log_individual_events' name='cs_log_individual_events' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log individual docker image vulnerability events</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='cs_log_summary_events' name='cs_log_summary_events' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log docker image summary events</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='cs_multi_threading_enabled' name='cs_multi_threading_enabled' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Enable multi-threading to download docker image vulnerabilities</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Number of threads to use for CS feed (max 10)</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='cs_num_threads' name='cs_num_threads' />" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Page size</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='cs_image_page_size' name='cs_image_page_size' />" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra filters for Docker Image API</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='cs_extra_params' name='cs_extra_params' />Enter as Elastic Search Query (e.g. a:1 or b.c:string OR a:1 and b.c:string). Following parameters are NOT allowed: pageNumber, pageSize, updated" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd8' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd8'>Container Security Settings for Containers</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='cs_log_individual_container_events' name='cs_log_individual_container_events' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log individual docker container vulnerability events</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='cs_log_container_summary_events' name='cs_log_container_summary_events' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log docker container summary events</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='cs_container_multi_threading_enabled' name='cs_container_multi_threading_enabled' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Enable multi-threading to download docker container vulnerabilities</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Number of threads</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='cs_container_num_threads' name='cs_container_num_threads' />Multi-threading is resource-intensive. Please set a value only between 2 to 10 (both inclusive)." +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Page size</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='cs_container_api_page_size' name='cs_container_api_page_size' />" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra filters for Containers</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='cs_container_extra_params' name='cs_container_extra_params' />Please refer Qualys UI help for search filter. Following parameters are NOT allowed: pageNo, pageSize, updated" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd9' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd9'>FIM Settings for Events</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Page size</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='fim_events_page_size' name='fim_events_page_size' />" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra filters for FIM Events API</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='fim_events_extra_params' name='fim_events_extra_params' />Enter as Elastic Search Query (e.g. a:1 or b.c:string OR a:1 and b.c:string). Following parameters are NOT allowed: pageNumber, pageSize, dateTime" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd10' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd10'>FIM Settings for Ignored Events</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Page size</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='fim_ignored_events_page_size' name='fim_ignored_events_page_size' />" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra filters for FIM Ignored Events API</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='fim_ignored_events_extra_params' name='fim_ignored_events_extra_params' />Enter as Elastic Search Query (e.g. a:1 or b.c:string OR a:1 and b.c:string). Following parameters are NOT allowed: pageNumber, pageSize, dateTime" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd11' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd11'>FIM Settings for Incidents</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Page size</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='fim_incidents_page_size' name='fim_incidents_page_size' />" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra filters for FIM Incidents API</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='fim_incidents_extra_params' name='fim_incidents_extra_params' />Enter as Elastic Search Query (e.g. a:1 or b.c:string OR a:1 and b.c:string). Following parameters are NOT allowed: pageNumber, pageSize, dateTime" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd12' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd12'>Endpoint Detection and Response Settings</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Page size</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='ioc_events_pageSize' name='ioc_events_pageSize' />" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra filters for Endpoint Detection and Response API</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='ioc_extra_params' name='ioc_extra_params' />Enter as Elastic Search Query (e.g. a:1 or b.c:string OR a:1 and b.c:string)." +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd13' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd13'>Activity Log Settings</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra parameters for Activity Log API</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='al_extra_params' name='al_extra_params' />Note: Enter as URL Query (e.g. a=1&amp;b=string) or as JSON (e.g. {\"a\":1, \"b\": \"string\"}). Following parameters are NOT allowed: action, output_format, since_datetime, until_datetime" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +
                                                    
                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd14' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd14'>Knowledge Base Settings</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_kb_additional_fields' name='log_kb_additional_fields' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log additional fields (SOLUTION, CONSEQUENCE, DIAGNOSIS)</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='is_index_knowledgebase' name='is_index_knowledgebase' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Index the knowledge base. CSV lookup file will NOT be created.</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Note: This feature is helpful if you are using distributed setup.</label>" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd17' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd17'>Secure Enterprise Mobility Settings</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_individual_sem_detection' name='log_individual_sem_detection' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log Individual Asset Detections</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='log_sem_asset_summary' name='log_sem_asset_summary' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Log Asset Summary events</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Number of SEM records per API request</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='sem_truncation_limit' name='sem_truncation_limit' />" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Extra parameters to SEM API</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='extra_sem_params' name='extra_sem_params' /> Enter as URL Query (e.g. a=1&amp;b=string). Following parameters are NOT allowed: action, detection_updated_since, detection_updated_before, truncation_limit" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd18' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd18'>Policy Compliance Reporting Service Settings</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='evidenceRequired' name='evidenceRequired' > &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Add additional field evidence</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Number of Policy Ids to use for Resolve Host Ids API (max 10)</label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='pcrs_num_count_for_pid' name='pcrs_num_count_for_pid' />" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd15' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd15'>Proxy Configuration</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='use_proxy' name='use_proxy' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Use a proxy server for Qualys API requests</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <label>Proxy server and credentials </label>" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <input type='text' id='proxy_server' name='proxy_server' />(e.g. 10.10.10.2:8080 OR username:password@10.10.10.2:8080)" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "  <div class='tab'>" +
                                "    <input type='radio' id='rd16' name='rd' class='disabled-radio'>" +
                                "    <label class='tab-label' for='rd16'>More Settings</label>" +
                                "    <div class='tab-content'>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='enable_debug' name='enable_debug' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Enable debug logs</label>" +
                                "           </div>" +
                                "       </div>" +
                                "       <div class='row'>" +
                                "           <div class='col-25'>" +
                                "               <input type='checkbox' id='preserve_api_output' name='preserve_api_output' /> &nbsp; &nbsp;" +
                                "           </div>" +
                                "           <div class='col-75'>" +
                                "               <label>Enable to preserve the XML/JSON files of API output</label>" +
                                "           </div>" +
                                "       </div>" +
                                "    </div>" +
                                "  </div>" +

                                "    <div class='row'>" +
                                "        <br />" +
                                "        <input type='hidden' id='is_configured' name='is_configured' />" +
                                "        <input type='button' name='cancel_button' class='cancel_button' value='Cancel' /> &nbsp;&nbsp; <input type='submit' name='setup_button' class='setup_button' value='Save' />" +
                                "    </div>" +
                                "</div>";

                return template_string;
            },
        }); // End of ExampleView class declaration

        return ExampleView;
    }, // End of require asynchronous module definition function
); // End of require statement