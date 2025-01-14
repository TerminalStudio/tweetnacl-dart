A fork of tweetnacl-dart with up-to-date dependencies and automated tests.

- `fixnum: ^1.0.0`
- `convert: ^3.0.0`
- [![test](https://github.com/TerminalStudio/tweetnacl-dart/actions/workflows/dart.yml/badge.svg)](https://github.com/TerminalStudio/tweetnacl-dart/actions/workflows/dart.yml)

## Usage

A simple usage example:

```dart
import 'package:tweetnacl/tweetnacl.dart';
import "dart:convert";
import 'dart:typed_data';

void main(){
  KeyPair kp = Signature.keyPair();
  print("secretKey: \"${TweetNaclFast.hexEncodeToString(kp.secretKey)}\"");
  print("publicKey: \"${TweetNaclFast.hexEncodeToString(kp.publicKey)}\"");

  Uint8List bytes = utf8.encode("test string");
  
  Signature s1 = Signature(null, kp.secretKey);
  Uint8List signature = s1.detached(bytes);
  print("signature: \"${TweetNaclFast.hexEncodeToString(signature)}\"");

  Signature s2 = Signature(kp.publicKey, null);
  bool result = s2.detached_verify(bytes,  signature);
  print("verify: \"${result}\"");
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/jspschool/tweetnacl-dart/issues
