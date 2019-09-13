# Asymmetric Key Encryption

## Class diagrams

Base API classes.
 
 ``` plantuml
 @startuml
 abstract class ByteList
 
 class FixedByteList {
   int keyLength
 }
 
 abstract class AsymmetricKey
 abstract class AsymmetricPrivateKey {
   AsymmetricKey public
   AsymmetricPrivateKey generate()
 }
 
 class PrivateKey
 class PublicKey
 
 abstract class Sign {
   Verify verifyKey;
   ByteList sign(List<int> message);
 }
 
 abstract class Verify {
   bool verify(ByteList message, Signature signature)
 }
 
 class SigningKey
 class VerifyKey
 class Signature
 
 FixedByteList .up.|> ByteList
 AsymmetricPrivateKey -left-|> AsymmetricKey
 AsymmetricPrivateKey .left.> AsymmetricKey
 
 PrivateKey -up-|> FixedByteList
 PrivateKey -left-|> AsymmetricPrivateKey
 
 PublicKey -up-|> FixedByteList
 PublicKey .right.|> AsymmetricKey
 
 SigningKey -up-|> PrivateKey
 SigningKey .left.|> Sign
 
 VerifyKey -up-|> PublicKey
 VerifyKey .right.|> Verify
 
 FixedByteList -up-|> Signature
 Sign .left.> Verify
 @enduml
 ```

 ## Tools

 - Use [Plantext.com](https://www.planttext.com/) or [PlantUML](http://www.plantuml.com/plantuml)'s services
 - Use Plantuml as Proxy see details in [Example](#Example)
 
# Example


 ![Example](http://www.plantuml.com/plantuml/proxy?src=https://raw.github.com/plantuml/plantuml-server/master/src/main/webapp/resource/test2diagrams.txt)

As proxy or rendered images (PNG or SVG)
``` 
 http://www.plantuml.com/plantuml/proxy?src=https://raw.github.com/plantuml/plantuml-server/master/src/main/webapp/resource/test2diagrams.txt
![PlantUML model](http://plantuml.com:80/plantuml/png/png/SyfFKj2rKt3CoKnELR1Io4ZDoSa70000)
![PlantUML model](http://plantuml.com:80/plantuml/svg/png/SyfFKj2rKt3CoKnELR1Io4ZDoSa70000)
```