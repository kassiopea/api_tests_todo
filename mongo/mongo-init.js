db = db.getSiblingDB('DevTodoDB');

//db.createUser(
//  {
//    user: 'test_admin',
//    pwd: '123456',
//    roles: [{ role: 'readWrite', db: 'DevTodoDB' }],
//  },
//);

db.createCollection('colors');

db.colors.insertMany([
    {"color": "Black", "hex_color": "#000000"},
    {"color": "Grey", "hex_color": "#bababa"},
    {"color": "Dark grey", "hex_color": "#b2b2b2"},
    {"color": "Orange", "hex_color": "#ffa500"},
    {"color": "Dark navy", "hex_color": "#576675"}
])
