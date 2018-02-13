/*
 * build.appdev.js
 *
 * This file is intended to be used by the appdev build command line tool.
 *
 * This file exports the actual command() to run when trying to build this 
 * application/widget.
 *
 * Create your command() to run from the [root]/assets  directory.
 *
 */


var AD = require('ad-utils');
var path = require('path');
var async = require('async');
var fs = require('fs');
var transform = require("steal-tools").transform;


module.exports = {

    /* 
     * command()
     *
     * This is the actual command to execute.
     * 
     * This method is required.
     *
     * @param {fn} cb   The callback fn to run when command is complete.
     *                  The callback follows the usual node: cb(err) format.
     */
    command:function(builder, cb) {

        var self = this;

        // this is expected to be running the /assets directory

        // build command:  ./cjs steal/buildjs OpsPortal opstools/Relay


        //// NOTE: the build command will attempt to rebuild OpsPortal/production.[js,css].  We don't
        //// want to do that here, so we'll have to backup the original files and return them when we are done.

        var backUpName= '';
        var backUpCSS = '';

        async.series([


            // step 1:  backup the original OpsPortal/production.* files.
            function (next) {


                backUpName = builder.backupProduction({ base:'OpsPortal', file:'production.js'});
                backUpCSS = builder.backupProduction({ base:'OpsPortal', file:'production.css'});

                next();
            },


            // step 2:  build js files
            function (next) {

                AD.log('<green>building</green> opstools/Relay JS files');

                // Minify js/ejs files
                transform({
                    main: path.join('opstools', 'Relay', 'Relay'),
                    config: "stealconfig.js"
                }, {
                        minify: true,
                        ignore: [
                            /^.*(.css)+/, // Ignore css files
                            /^(?!opstools\/Relay.*)/, // Ignore all are not plugin scripts
                        ]
                    }).then(function (transform) {
                        // Get the main module and it's dependencies as a string
                        var main = transform();

                        fs.writeFile(path.join('opstools', 'Relay', 'production.js'), main.code, "utf8", function (err) {
                            if (err) {
                                AD.log.error('<red>could not write minified opstools/Relay JS file !</red>');
                                next(err);
                            }

                            next();
                        });
                    })
                    .catch(function (err) {
                        AD.log.error('<red>could not complete opstools/Relay JS build!</red>', err);
                        next(err);
                    });
            },

            // step 3:  build css files
            function (next) {
                AD.log('<green>building</green> opstools/Relay CSS files');

                // Minify css files
                transform({
                    main: path.join('opstools', 'Relay', 'Relay'),
                    config: "stealconfig.js"
                }, {
                        minify: true,
                        ignore: [
                            /^(?!.*(.css)+)/, // Get only css files
                            /^(?!opstools\/Relay.*)/, // Ignore all are not plugin scripts
                        ]
                    }).then(function (transform) {
                        var main = transform();

                        fs.writeFile(path.join('opstools', 'Relay', 'production.css'), main.code, "utf8", function (err) {
                            if (err) {
                                AD.log.error('<red>could not write minified opstools/Relay CSS file !</red>');
                                next(err);
                            }

                            next();
                        });
                    })
                    .catch(function (err) {
                        AD.log.error('<red>could not complete opstools/Relay CSS build!</red>', err);
                        next(err);
                    });
            },



            // step 4:  replace our original OpsPortal/production.* files
            function(next) {

                builder.replaceProduction({ base:'OpsPortal', file:'production.js', backup: backUpName });
                builder.replaceProduction({ base:'OpsPortal', file:'production.css', backup: backUpCSS });
                next();
            },



            // step 5:  patch our production.js to reference OpsPortal/production.js 
            function(next) {

                var patches = [
                    { file:path.join('opstools', 'Relay', 'production.js'), tag:'packages/OpsPortal-Relay.js', replace:'OpsPortal/production.js'}
                ];

                builder.patchFile(patches, next);
            }


        ], function( err, results) {

            cb(err);
        });

    }
}

