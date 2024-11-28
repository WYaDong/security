// -*- coding: utf-8 -*-
// Project    : Security
// File       : AES.ets
// Time       ：2024/6/20
// Author     ：ya dong
// Copyright © 2024 CL. All rights reserved.

import { buffer } from '@kit.ArkTS'
import { cryptoFramework } from '@kit.CryptoArchitectureKit'
import { AESKeyEnum } from '../Security'
import { HiLogUtils } from './log/HiLogUtils'

export enum AESPKCSEnum {
  PKCS7 = 'PKCS7',
  PKCS5 = 'PKCS5'
}

export enum AESMSEnum {
  CBC = 'CBC',
  GCM = 'GCM',
  ECB = 'ECB'
}

export class AES {
  private async genSymKeyByData(symKeyData: Uint8Array, aesType: AESKeyEnum) {
    let symKeyBlob: cryptoFramework.DataBlob = { data: symKeyData }
    let aesGenerator = cryptoFramework.createSymKeyGenerator(aesType)
    let symKey = await aesGenerator.convertKey(symKeyBlob)
    return symKey
  }

  async decryptWithString(sourceData: Uint8Array, keyString: string, ivString: string, aesType: AESKeyEnum,
    aesMSType: AESMSEnum, aesPKCSType: AESPKCSEnum): Promise<Uint8Array> {
    let key = new Uint8Array(buffer.from(keyString, 'utf-8').buffer)
    let iv = new Uint8Array(buffer.from(ivString, 'utf-8').buffer)
    return await this.decryptWithData(sourceData, key, iv, aesType, aesMSType, aesPKCSType)
  }

  async decryptWithData(sourceData: Uint8Array, keyData: Uint8Array, ivData: Uint8Array, aesType: AESKeyEnum,
    aesMSType: AESMSEnum, aesPKCSType: AESPKCSEnum): Promise<Uint8Array> {
    return await this.dealWithData(sourceData, keyData, ivData, aesType, aesMSType, aesPKCSType, true)
  }

  async encryptWithString(sourceString: string, keyString: string, ivString: string, aesType: AESKeyEnum,
    aesMSType: AESMSEnum, aesPKCSType: AESPKCSEnum): Promise<Uint8Array> {
    let key = new Uint8Array(buffer.from(keyString, 'utf-8').buffer)
    let iv = new Uint8Array(buffer.from(ivString, 'utf-8').buffer)
    return await this.encryptWithData(new Uint8Array(buffer.from(sourceString, 'utf-8')
      .buffer), key, iv, aesType, aesMSType, aesPKCSType)
  }


  async encryptWithData(sourceData: Uint8Array, keyData: Uint8Array, ivData: Uint8Array, aesType: AESKeyEnum,
    aesMSType: AESMSEnum, aesPKCSType: AESPKCSEnum): Promise<Uint8Array> {
    return await this.dealWithData(sourceData, keyData, ivData, aesType, aesMSType, aesPKCSType, false)
  }

  async dealWithData(sourceData: Uint8Array, keyData: Uint8Array, ivData: Uint8Array, aesType: AESKeyEnum,
    aesMSType: AESMSEnum, aesPKCSType: AESPKCSEnum, isDecrypt: boolean): Promise<Uint8Array> {
    try {
      // key
      let symKey = await this.genSymKeyByData(keyData, aesType)
      // source
      let plainText: cryptoFramework.DataBlob = {
        data: sourceData
      }
      // iv
      let ivBlob: cryptoFramework.DataBlob = {
        data: ivData
      }
      let symIv: cryptoFramework.IvParamsSpec = {
        algName: 'IvParamsSpec',
        iv: ivBlob
      }
      // 加/解密
      let cipher = cryptoFramework.createCipher(aesType + '|' + aesMSType + '|' + aesPKCSType)
      await cipher.init(isDecrypt ? cryptoFramework.CryptoMode.DECRYPT_MODE : cryptoFramework.CryptoMode.ENCRYPT_MODE,
        symKey, symIv)
      let cipherData = await cipher.doFinal(plainText)
      return cipherData.data
    } catch (e) {
      HiLogUtils.error(JSON.stringify(e))
      return new Uint8Array()
    }
  }
}

