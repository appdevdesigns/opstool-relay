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
        },
        
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
    },
    
    
    
    /**
     * Finds the RSA public keys for all users of a given application.
     *
     * @param {string} application
     * @return {Promise}
     *      {
     *          <user>: <rsa_public_key>,
     *          ...
     *      }
     */
    findPublicKeys: function(application) {
        return new Promise((resolve, reject) => {
            RelayApplicationUser.query(`
                
                SELECT
                    au.user,
                    u.rsa_public_key
                FROM
                    relay_application_user au
                    JOIN relay_user u
                        ON au.ren_id = u.ren_id
                WHERE
                    au.application = ?
                    
            `, [application], (err, list) => {
                if (err) reject(err);
                else {
                    // Convert results in object indexed by user GUID
                    var results = {};
                    list.forEach((row) => {
                        var userGUID = row.user;
                        results[userGUID] = row.rsa_public_key;
                    });
                    resolve(results);
                }
            });
        });
    }
    

};
