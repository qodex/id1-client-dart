# Dart/Flutter client for id1 API

https://github.com/qodex/id1

#### Example:

    var id1 = Id1ClientHttp(apiUrl: apiUrl);
    
    if (!(await id1.authenticate(id, privateKeyPEM))) {
      print("failed to authenticate");
      return;
    }
    
    var key = Id1Key("$id/test/val");
    await id1.set(key, utf8.encode("Hello id1"));
    var val = await id1.get(key);
    print(utf8.decode(val ?? []));
    await id1.del(key);

  
