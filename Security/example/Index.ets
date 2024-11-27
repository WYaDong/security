// -*- coding: utf-8 -*-
// Project    : SecuritySDK
// File       : Index.ets
// Time       ：2024/6/25
// Author     ：ya dong
// Copyright © 2024 CL. All rights reserved.

import { hilog } from '@kit.PerformanceAnalysisKit';
import { buffer } from '@kit.ArkTS';
import { Security } from '../Index';
import { AESKeyEnum } from '../src/main/ets/components/Security';

@Entry
@Component
struct Index {
  build() {
    Column() {
      Button('md5', { type: ButtonType.Normal, stateEffect: true })
        .fontSize(20)
        .fontWeight(FontWeight.Bold)
        .borderRadius(8)
        .width('80%')
        .height(55)
        .margin({ top: 15 })
        .backgroundColor(Color.Blue)
        .onClick(async () => {
          let md5 = await Security.md5('abcdef')
          hilog.info(1000, 'Securitytag', 'md5: ' + md5.hex())
        })
      Button('HMacSha、sha ', { type: ButtonType.Normal, stateEffect: true })
        .fontSize(20)
        .fontWeight(FontWeight.Bold)
        .borderRadius(8)
        .width('80%')
        .height(55)
        .margin({ top: 15 })
        .backgroundColor(Color.Blue)
        .onClick(async () => {
          let result256 = await Security.HMacSha256('abcdef', '123456')
          hilog.info(1000, 'Securitytag', 'HMacSha256: ' + result256.hex())

          let resultSha256 = await Security.sha256('abcdef')
          hilog.info(1000, 'Securitytag', 'sha256: ' + resultSha256.hex())
        })

      Button('aes 加解密', { type: ButtonType.Normal, stateEffect: true })
        .fontSize(20)
        .fontWeight(FontWeight.Bold)
        .borderRadius(8)
        .width('80%')
        .height(55)
        .margin({ top: 15 })
        .backgroundColor(Color.Blue)
        .onClick(async () => {
          let plainText = '1662100123' //待加密内容
          let key = 'afae4ec844ed14ca' //长度16，实际使用时建议使用安全随机数生成，不能硬编码在代码中
          let iv = '67e7d725dfe24ca1' //长度16，实际使用时建议使用安全随机数生成，不能硬编码在代码中
          let aesRst = await Security.aesEncrypt(plainText, key, iv)
          hilog.info(1000, 'Securitytag', 'aesEncrypt: ' + aesRst.hex())

          let aesRst2 = await Security.aesEncryptWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
            .buffer),
            new Uint8Array(buffer.from(iv, 'utf-8').buffer))
          hilog.info(1000, 'Securitytag', 'aesEncryptWithData: ' + aesRst2.hex())


          let aseDec = await Security.aesDecrypt(aesRst.data(), key, iv)
          hilog.info(1000, 'Securitytag', 'aesDecrypt: ' + aseDec.utf8String())

          let aseDec2 = await Security.aesDecryptWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
            .buffer),
            new Uint8Array(buffer.from(iv, 'utf-8').buffer))
          hilog.info(1000, 'Securitytag', 'aesEncryptWithData: ' + aseDec2.utf8String())


          key = 'afae4ec844ed14ca12345678' //长度16，实际使用时建议使用安全随机数生成，不能硬编码在代码中
          aesRst = await Security.aesEncryptWithSymAlgName(plainText, key, iv, AESKeyEnum.AES192)
          hilog.info(1000, 'Securitytag', 'aesEncrypt192: ' + aesRst.hex())

          aesRst2 = await Security.aesEncryptWithSymAlgNameWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
            .buffer),
            new Uint8Array(buffer.from(iv, 'utf-8').buffer), AESKeyEnum.AES192)
          hilog.info(1000, 'Securitytag', 'aesEncryptWithData192: ' + aesRst2.hex())


          aseDec = await Security.aesDecryptWithSymAlgName(aesRst.data(), key, iv, AESKeyEnum.AES192)
          hilog.info(1000, 'Securitytag', 'aesDecrypt192: ' + aseDec.utf8String())

          aseDec2 = await Security.aesDecryptWithSymAlgNameWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
            .buffer),
            new Uint8Array(buffer.from(iv, 'utf-8').buffer), AESKeyEnum.AES192)
          hilog.info(1000, 'Securitytag', 'aesEncryptWithData192: ' + aseDec2.utf8String())


          key = 'afae4ec844ed14ca1234567812345678' //长度16，实际使用时建议使用安全随机数生成，不能硬编码在代码中
          aesRst = await Security.aesEncryptWithSymAlgName(plainText, key, iv, AESKeyEnum.AES256)
          hilog.info(1000, 'Securitytag', 'aesEncrypt256: ' + aesRst.hex())

          aesRst2 = await Security.aesEncryptWithSymAlgNameWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
            .buffer),
            new Uint8Array(buffer.from(iv, 'utf-8').buffer), AESKeyEnum.AES256)
          hilog.info(1000, 'Securitytag', 'aesEncryptWithData256: ' + aesRst2.hex())


          aseDec = await Security.aesDecryptWithSymAlgName(aesRst.data(), key, iv, AESKeyEnum.AES256)
          hilog.info(1000, 'Securitytag', 'aesDecrypt256: ' + aseDec.utf8String())

          aseDec2 = await Security.aesDecryptWithSymAlgNameWithData(aesRst.data(), new Uint8Array(buffer.from(key, 'utf-8')
            .buffer),
            new Uint8Array(buffer.from(iv, 'utf-8').buffer), AESKeyEnum.AES256)
          hilog.info(1000, 'Securitytag', 'aesEncryptWithData256: ' + aseDec2.utf8String())

          hilog.info(1000, 'Securitytag', 'aesDecryptWithString: ' + (await Security.aesDecryptWithHexString('323342D5B1B8558F002A75BE1EAEF305',
            'afae4ec844ed14ca', '67e7d725dfe24ca1')).utf8String())

        })

    }
    .width('100%')
  }
}