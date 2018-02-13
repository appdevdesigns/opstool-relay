/**
 * RelayData
 * @module      :: Model
 */

var async = require('async');
var _ = require('lodash');

module.exports = {
    
    tableName: 'relay_application_user',
    
    autoCreatedAt: false,
    autoUpdatedAt: false,
    autoPK: false,
    migrate: 'safe',
    
    attributes: {
        id: {
            type: 'integer',
            size: 11,
            primaryKey: true,
            autoIncrement: true
        },
        
        // User ID from the VPN's perspective
        ren_id: {
            type: 'integer',
            size: 11,
        },
        
        // User ID from the app's perspective
        user: {
            type: 'mediumtext'
        },
        
        application: {
            type: 'string',
            size: 80,
        }
        
        aes_key: {
            type: 'mediumtext',
        },
        
        //// Instance model methods
        
        toJSON: function() {
            // This model's data is not intended to be sent to the client.
            // But if for some reason that is done, the encryption key must
            // remain secret.
            var obj;
            if (this.toObject) {
                obj = this.toObject();
            } else {
                obj = _.clone(this);
            }
            delete obj.aes_key;
            return obj;
        }
    },
    
    ////
    //// Life cycle callbacks
    ////
    
    
    
    ////
    //// Model class methods
    ////
    
    /**
     * Populate the user entries for a given application.
     * Users who are found in RelayUser but not yet in RelayApplicationUser
     * will have entries created.
     *
     * The `ren_id` values will be copied from RelayUser.
     * The `user` fields will have new UUIDs generated.
     *
     * @param {string} application
     * @return {Promise}
     */
    initializeApplicationUsers: function(application) {
        return new Promise((resolve, reject) => {
            RelayApplicationUser.query(`
                
                INSERT INTO relay_application_user
                (ren_id, user, application)
                (
                    SELECT
                        u.ren_id, UUID(), ?
                    FROM
                        relay_user u
                        LEFT JOIN relay_application_user au
                            ON u.ren_id = au.ren_id
                            AND au.application = ?
                    WHERE
                        au.id IS NULL
                )
            
            `, [application, application], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }
    

};
