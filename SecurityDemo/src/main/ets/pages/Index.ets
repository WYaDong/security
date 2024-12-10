import { hilog } from '@kit.PerformanceAnalysisKit'
import { Security } from '@yd/security'
import { buffer } from '@kit.ArkTS'
import { AESKeyEnum } from '@yd/security/src/main/ets/components/Security'

@Entry
@Component
struct Index {
  @State message: string = '结果展示：'
  private logTag: string = 'securityTag'

  build() {
    Flex({ direction: FlexDirection.Column }) {
      Column() {
        Text(this.message)
          .textAlign(TextAlign.Start)
          .padding(20)
          .fontColor(Color.White)
      }
      .width('100%')
      .height('30%')
      .backgroundColor(Color.Black)
      .alignItems(HorizontalAlign.Start)

      Column() {
        Button('md5', { type: ButtonType.Normal, stateEffect: true })
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .borderRadius(8)
          .width('80%')
          .height(45)
          .margin({ top: 15 })
          .backgroundColor(Color.Blue)
          .onClick(async () => {
            let md5 = await Security.md5('abcdef')
            this.message = '结果展示：'
            this.message = this.message + '\n' + 'md5: ' + md5.hex() + "  code:" + md5.code
            hilog.info(1000, this.logTag, this.message)
          })
        Button('HMacSha', { type: ButtonType.Normal, stateEffect: true })
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .borderRadius(8)
          .width('80%')
          .height(45)
          .margin({ top: 15 })
          .backgroundColor(Color.Blue)
          .onClick(async () => {
            let result256 = await Security.hMacSha256('abcdef', '123456')
            this.message = '结果展示：'
            this.message = this.message + '\n' + 'HMacSha256: ' + result256.hex() + "  code:" + result256.code
            hilog.info(1000, this.logTag, this.message)
          })

        Button('sha ', { type: ButtonType.Normal, stateEffect: true })
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .borderRadius(8)
          .width('80%')
          .height(45)
          .margin({ top: 15 })
          .backgroundColor(Color.Blue)
          .onClick(async () => {
            let resultSha256 = await Security.sha256('abcdef')
            this.message = '结果展示：'
            this.message = this.message + '\n' + 'sha256: ' + resultSha256.hex() + "  code:" + resultSha256.code
            hilog.info(1000, this.logTag, this.message)
          })

        Button('aes128 加解密', { type: ButtonType.Normal, stateEffect: true })
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .borderRadius(8)
          .width('80%')
          .height(45)
          .margin({ top: 15 })
          .backgroundColor(Color.Blue)
          .onClick(async () => {
            let plainText = '1662100123' //待加密内容
            let key = 'afae4ec844ed14ca' //长度16
            let iv = '67e7d725dfe24ca1'
            let aesRst = await Security.aesEncrypt(plainText, key, iv)
            this.message = '结果展示：'
            this.message = this.message + '\n' + 'aesEncrypt: ' + aesRst.hexLower() + "  code:" + aesRst.code
            hilog.info(1000, 'Securitytag', this.message)

            // 加密
            let aesRst2 = await Security.aesEncryptWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
              .buffer),
              new Uint8Array(buffer.from(iv, 'utf-8').buffer))
            this.message = this.message + '\n' + 'aesEncryptWithData: ' + aesRst2.hex()
            hilog.info(1000, this.logTag, this.message)

            // 解密
            let aseDec = await Security.aesDecrypt(aesRst.data(), key, iv)
            this.message = this.message + '\n' + 'aesDecrypt: ' + aseDec.utf8String()
            hilog.info(1000, this.logTag, this.message)

            let aseDec2 = await Security.aesDecryptWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
              .buffer),
              new Uint8Array(buffer.from(iv, 'utf-8').buffer))
            this.message = this.message + '\n' + 'aesEncryptWithData: ' + aseDec2.utf8String()
            hilog.info(1000, this.logTag, this.message)


            hilog.info(1000, this.logTag,
              'aesDecryptWithString: ' + (await Security.aesDecryptWithHexString('323342D5B1B8558F002A75BE1EAEF305',
                'afae4ec844ed14ca', '67e7d725dfe24ca1')).utf8String())
          })

        Button('aes192 加解密', { type: ButtonType.Normal, stateEffect: true })
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .borderRadius(8)
          .width('80%')
          .height(45)
          .margin({ top: 15 })
          .backgroundColor(Color.Blue)
          .onClick(async () => {
            let plainText = '1662100123' //待加密内容
            let key = 'afae4ec844ed14ca12345678' //长度24
            let iv = '67e7d725dfe24ca1'

            // 加密
            let aesRst = await Security.aesEncryptWithSymAlgName(plainText, key, iv, AESKeyEnum.AES192)
            this.message = '结果展示：'
            this.message = this.message + '\n' + 'aesEncrypt192: ' + aesRst.hex() + "  code:" + aesRst.code
            hilog.info(1000, this.logTag, this.message)

            let aesRst2 =
              await Security.aesEncryptWithSymAlgNameWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
                .buffer),
                new Uint8Array(buffer.from(iv, 'utf-8').buffer), AESKeyEnum.AES192)
            this.message = this.message + '\n' + 'aesEncryptWithData192: ' + aesRst2.hex()
            hilog.info(1000, this.logTag, this.message)


            // 解密
            let aseDec = await Security.aesDecryptWithSymAlgName(aesRst.data(), key, iv, AESKeyEnum.AES192)
            this.message = this.message + '\n' + 'aesDecrypt192: ' + aseDec.utf8String()
            hilog.info(1000, this.logTag, this.message)

            let aseDec2 =
              await Security.aesDecryptWithSymAlgNameWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
                .buffer),
                new Uint8Array(buffer.from(iv, 'utf-8').buffer), AESKeyEnum.AES192)
            this.message = this.message + '\n' + 'aesEncryptWithData192: ' + aseDec2.utf8String()
            hilog.info(1000, this.logTag, this.message)
          })

        Button('aes256 加解密', { type: ButtonType.Normal, stateEffect: true })
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .borderRadius(8)
          .width('80%')
          .height(45)
          .margin({ top: 15 })
          .backgroundColor(Color.Blue)
          .onClick(async () => {
            let plainText = '1662100123' //待加密内容
            let key = 'afae4ec844ed14ca1234567812345678' //长度32
            let iv = '67e7d725dfe24ca1'

            // 加密
            let aesRst = await Security.aesEncryptWithSymAlgName(plainText, key, iv, AESKeyEnum.AES256)
            this.message = '结果展示：'
            this.message = this.message + '\n' + 'aesEncrypt256: ' + aesRst.hex() + "  code:" + aesRst.code
            hilog.info(1000, this.logTag, this.message)

            let aesRst2 =
              await Security.aesEncryptWithSymAlgNameWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
                .buffer),
                new Uint8Array(buffer.from(iv, 'utf-8').buffer), AESKeyEnum.AES256)
            this.message = this.message + '\n' + 'aesEncryptWithData256: ' + aesRst2.hex()
            hilog.info(1000, this.logTag, this.message)


            // 解密
            let aseDec = await Security.aesDecryptWithSymAlgName(aesRst.data(), key, iv, AESKeyEnum.AES256)
            this.message = this.message + '\n' + 'aesDecrypt256: ' + aseDec.utf8String()
            hilog.info(1000, this.logTag, this.message)

            let aseDec2 =
              await Security.aesDecryptWithSymAlgNameWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
                .buffer),
                new Uint8Array(buffer.from(iv, 'utf-8').buffer), AESKeyEnum.AES256)
            this.message = this.message + '\n' + 'aesEncryptWithData256: ' + aseDec2.utf8String()
            hilog.info(1000, this.logTag, this.message)
          })
      }
      .width('100%')
    }
  }
}