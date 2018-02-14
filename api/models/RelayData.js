/**
 * RelayData
 * @module      :: Model
 */

var async = require('async');
var _ = require('lodash');
var CryptoJS = require('crypto-js');
var crypto = require('crypto');

module.exports = {
    
    tableName: 'relay_data',
    
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
        
        ren_id: {
            type: 'integer',
            size: 11,
        },
        
        application: {
            type: 'string',
            size: 80,
        },
        
        // "aes", "rsa", or "plaintext"
        type: {
            type: 'string',
            size: 8,
        },
        
        // "vpn" or "app"
        destination: {
            type: 'string',
            size: 8
        },
        
        data: {
            type: 'longtext',
        },
        
        ///
        /// Instance methods
        ///
        
        /**
         * Decrypts `this.data`. Object instance's properties will be modified,
         * but changes are not saved to the DB yet.
         *
         * If `type` is 'rsa', the rsa_private_key from RelayUser will be used.
         * If `type` is 'aes', the matching aes_key from RelayApplicationUser
         * will be used.
         * Any other `type` will be treated as plaintext.
         * 
         * @return {Promise}
         *      Resolves with a JSON object parsed from the decrypted data
         */
        decrypt: function() {
            return new Promise((resolve, reject) => {
                Promise.resolve()
                .then(() => {
                    // Find encryption key
                    if (this.type == 'rsa') {
                        return RelayUser.find({ ren_id: this.ren_id });
                    }
                    else if (this.type == 'aes') {
                        return RelayApplicationUser.find({ ren_id: this.ren_id, application: this.application });
                    }
                    else {
                        // Treat as plaintext
                        return null;
                    }
                })
                .then((list) => {
                    if (this.type == 'rsa' && list[0]) {
                        var key = list[0].rsa_private_key;
                        try {
                            var plaintext = crypto.privateDecrypt(
                                {
                                    key: key,
                                    padding: crypto.constants.RSA_NO_PADDING
                                    //padding: crypto.constants.RSA_PKCS1_PADDING
                                    //padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
                                },
                                Buffer.from(this.data, 'base64')
                            );
                            if (plaintext) {
                                this.data = plaintext.toString();
                                this.type = 'plaintext';
                            }
                        } catch (err) {
                            // could not decrypt
                            console.log('Unable to decrypt RSA', err);
                        }
                    }
                    else if (this.type == 'aes' && list[0]) {
                        // Expected format of encrypted data:
                        // <base64 encoded ciphertext>:::<hex encoded IV>
                        var key = list[0].aes_key;
                        var dataParts = this.data.split(':::');
                        var ciphertext = dataParts[0];
                        var iv = dataParts[1];
                        
                        try {
                            var decrypted = CryptoJS.AES.decrypt(
                                ciphertext, 
                                CryptoJS.enc.Hex.parse(key),
                                { iv: CryptoJS.enc.Hex.parse(iv) }
                            );
                            var plaintext = decrypted.toString(CryptoJS.enc.Utf8);
                            
                            /*
                            var decipher = crypto.createDecipheriv(
                                'aes-256-cbc', 
                                Buffer.from(key, 'hex'), 
                                Buffer.from(iv, 'hex')
                            );
                            var plaintext = decipher.update(ciphertext, 'hex', 'utf8');
                            plaintext += decipher.final('utf8');
                            */
                            
                            if (plaintext) {
                                this.data = plaintext;
                                this.type = 'plaintext';
                            }
                        } catch (err) {
                            // could not decrypt
                            console.log('Unable to decrypt AES', err);
                        }
                    }
                    
                    var result;
                    try {
                        result = JSON.parse(this.data);
                    } catch (err) {
                        result = this.data;
                    }
                    
                    resolve(result);
                })
                .catch((err) => {
                    reject(err);
                });
            });
        }
        
        
    },
    
    ////
    //// Life cycle callbacks
    ////
    
    
    
    ////
    //// Model class methods
    ////
    
    /**
     * Import incoming data from the external relay server.
     * 
     * @param {string} application
     * @param {array} list
     *      Array of raw data from the external relay server
     *      [
     *          { user: "1db00806-c85b-11e7-a7c3-00163e63826a", type : "aes", data: "encrypted data" },
     *          { user: "1db00806-c85b-11e7-a7c3-00163e63826a", type : "rsa", data: "encrypted data" },
     *          ...
     *      ]
     * @return {Promise}
     */
    importData: function(application, list) {
        return new Promise((resolve, reject) => {
            if (!Array.isArray(list)) {
                reject(new TypeError('list'));
            }
            else {   
                async.each(list, (packet, next) => {
                    // Map application user to ren_id
                    RelayApplicationUser.find({ user: packet.user, application: application })
                    .then((userList) => {
                        if (!userList || !userList[0]) {
                            console.log('No local user match when importing from relay', packet);
                        }
                        else {
                            var renID = userList[0].ren_id;
                            return RelayData.create({
                                ren_id: renID,
                                application: application,
                                destination: 'vpn',
                                data: packet.data
                            })
                        }
                    })
                    .then(() => {
                        next();
                    })
                    .catch(next);
                    
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            }
        });
    },
    
    
    /**
     * Export outgoing data intended for the external relay server.
     * 
     * @param {string} application
     * @return {Promise}
     */
    exportData: function(application) {
        return new Promise((resolve, reject) => {
            var results = [];
            var IDs = [];
            
            async.series([
                (next) => {
                    // Find outgoing data from the application
                    RelayData.query(`
                        
                        SELECT
                            d.id,
                            au.user AS 'user',
                            d.type AS 'type',
                            d.destination AS 'destination',
                            d.data AS 'data'
                        FROM
                            relay_data d
                            JOIN relay_application_user au
                                ON d.ren_id = au.ren_id
                                AND d.application = au.application
                        WHERE
                            d.application = ?
                            AND d.destination = 'app'
                            
                    `, [application], (err, list) => {
                        if (err) next(err);
                        else {
                            list.forEach((row) => {
                                IDs.push(row.id);
                                delete row.id;
                                results.push(row);
                            });
                            next();
                        }
                    });
                },
                
                (next) => {
                    // Remove sent data from the queue
                    RelayData.destroy({ id: IDs })
                    .exec((err) => {
                        if (err) next(err);
                        else next();
                    });
                },
                
            ], (err) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
    },
    
    
    /**
     * Fetch and decrypt incoming data for an application user.
     * 
     * @param {string} application
     * @param {integer} renID
     * @return {Promise}
     *      Resolves with array of JSON objects
     */
    retrieveUserData: function(application, renID) {
        return new Promise((resolve, reject) => {
            var IDs = []; // deletion queue
            var packets = [];
            var results = []; // final results
            
            // Find RSA packets first
            // (that's how the AES key is initially delivered)
            RelayData.find({ 
                application: application, 
                ren_id: renID, 
                type: 'rsa', 
                destination: 'vpn' }
            )
            .then((list) => {
                packets = list;
                
                // Decrypt RSA packets
                var tasks = [];
                packets.forEach((row) => {
                    tasks.push(row.decrypt());
                });
                return Promise.all(tasks);
            })
            .then((decrypted) => {
                var aesKey = null;
                
                decrypted.forEach((d) => {
                    if (Array.isArray(d)) {
                        d.forEach((o) => {
                            // Found AES key
                            if (o && o.aesKey) {
                                aesKey = o.aesKey;
                            }
                            // Normal data
                            else {
                                results.push(o);
                            }
                        });
                    }
                    else if (d) {
                        // Unexpected non-array data, but we can deal with it
                        results.push(d);
                    }
                    else {
                        // RSA decryption failed?
                    }
                });
                
                // Queue the decrypted packets for deletion
                packets.forEach((row) => {
                    // `type` was changed to 'plaintext' after decryption
                    if (row.type == 'plaintext') {
                        IDs.push(row.id);
                    }
                });
                
                if (aesKey) {
                    // Save AES key for this user
                    return RelayApplicationUser.update(
                        { ren_id: renID, application: application },
                        { aes_key: aesKey }
                    );
                } else {
                    return null;
                }
            })
            .then(() => {
                // Find AES and plaintext packets
                return RelayData.find({ 
                    application: application, 
                    ren_id: renID, 
                    type: { '!': 'rsa' }, 
                    destination: 'vpn' }
                );
            })
            .then((list) => {
                packets = list;
                
                // Decrypt AES packets
                var tasks = [];
                packets.forEach((row) => {
                    tasks.push(row.decrypt());
                });
                return Promise.all(tasks);
            })
            .then((decryptedResults) => {
                decryptedResults.forEach((d) => {
                    if (Array.isArray(d)) {
                        // Expected packet format is an array of JSON objects.
                        // Combine with results array.
                        results = results.concat(d);
                    }
                    else if (d) {
                        // Unexpected format, just add to results array
                        results.push(d);
                    }
                    else {
                        // AES decryption failed?
                    }
                });
                
                // Queue the decrypted packets for deletion
                packets.forEach((row) => {
                    if (row.type == 'plaintext') {
                        IDs.push(row.id);
                    }
                });
                
                // Delete decrypted packets. Packets that failed decryption will
                // be skipped.
                return RelayData.destroy({ id: IDs });
            })
            .then(() => {
                resolve(results);
            })
            .catch((err) => {
                reject(err);
            });
        });
    },
    
    
    /**
     * Encrypt data from an application user and queue it for transmission to 
     * the client app.
     * 
     * @param {string} application
     * @param {integer} renID
     * @param {object/array} data
     *      Either a single JSON object, or an array of objects.
     * @return {Promise}
     */
    queueUserData: function(application, renID, data) {
        return new Promise((resolve, reject) => {
            if (!Array.isArray(data)) {
                data = [data];
            }
            
            // Find application user's AES key
            RelayApplicationUser.find({ application: application, ren_id: renID })
            .then((list) => {
                if (!list || !list[0]) {
                    throw new Error(`User ${renID} not found for application ${application}`);
                }
                else if (!list[0].aes_key) {
                    throw new Error(`User ${renID} has not received AES key yet`);
                }
                else {
                    // Encrypt data
                    var plaintext = JSON.stringify(data);
                    var iv = crypto.randomBytes(16).toString('hex');
                    var ciphertext = CryptoJS.AES.encrypt(
                        plaintext,
                        CryptoJS.enc.Hex.parse(list[0].aes_key),
                        { iv: CryptoJS.enc.Hex.parse(iv) }
                    );
                    // <base64 encoded cipher text>:::<hex encoded IV>
                    var encoded = ciphertext.toString() + ':::' + iv;
                }
                
                // Add data to queue
                return RelayData.create({
                    ren_id: renID,
                    application: application,
                    type: 'aes',
                    destination: 'app',
                    data: encoded
                });
            })
            .then(() => {
                resolve();
            })
            .catch((err) => {
                reject(err);
            });
        });
    }
    

};
