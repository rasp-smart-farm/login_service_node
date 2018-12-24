var mysql = require('mysql');

var connection = mysql.createPool({
    connectionLimit: 100,
    host:'pi.toannhu.com',
    user:'root',
    password:'Anhhung94',
    database:'smart_farm',
    port: 3306,
    debug: false,
    multipleStatements: true
});

module.exports.connection = connection;