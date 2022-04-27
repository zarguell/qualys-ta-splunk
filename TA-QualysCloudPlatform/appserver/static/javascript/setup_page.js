"use strict";

var app_name = "TA-QualysCloudPlatform";

require.config({
    paths: {
        SetupViewQualysTA: "../app/" + app_name + "/javascript/views/setup_view_qualysta",
    },
});

require([
    // Splunk Web Framework Provided files
    "backbone", // From the SplunkJS stack
    "jquery", // From the SplunkJS stack
    // Custom files
    "SetupViewQualysTA",
], function(Backbone, jquery, SetupViewQualysTA) {
    var qualys_setup_view = new SetupViewQualysTA({
        // Sets the element that will be used for rendering
        el: jquery("#main_container"),
    });

    qualys_setup_view.render();
});
