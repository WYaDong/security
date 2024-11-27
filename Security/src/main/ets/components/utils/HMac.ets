// -*- coding: utf-8 -*-
// Project    : Security
// File       : HMac.ets
// Time       ：2024/6/19
// Author     ：ya dong
// Copyright © 2024 CL. All rights reserved.

import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { buffer } from '@kit.ArkTS';
import { HiLogUtils } from './log/HiLogUtils';

export enum HMACEnum {
  SHA1 = 'SHA1',
  SHA224 = 'SHA224',
  SHA256 = 'SHA256',
  SHA384 = 'SHA384',
  SHA512 = 'SHA512',
  SM3 = 'SM3'
}

export class HMac {
  private async genSymKeyByData(symKeyData: Uint8Array) {
    let symKeyBlob: cryptoFramework.DataBlob = { data: symKeyData }
    let aesGenerator = cryptoFramework.createSymKeyGenerator('HMAC')
    let symKey = await aesGenerator.convertKey(symKeyBlob)
    return symKey
  }

  async encrypt(sourceString: string, keyString: string, HMACType: HMACEnum): Promise<Uint8Array> {
    try {
      let keyData = new Uint8Array(buffer.from(keyString, 'utf-8').buffer)
      let key = await this.genSymKeyByData(keyData)
      let macAlgName = HMACType
      let sh256String = sourceString
      let mac = cryptoFramework.createMac(macAlgName)
      await mac.init(key)
      let messageData = new Uint8Array(buffer.from(sh256String, 'utf-8').buffer)
      let updateLength = 1000
      await mac.init(key)
      for (let i = 0; i < messageData.length; i += updateLength) {
        let updateMessage = messageData.subarray(i, i + updateLength);
        let updateMessageBlob: cryptoFramework.DataBlob = { data: updateMessage };
        await mac.update(updateMessageBlob);
      }
      let macResult = await mac.doFinal()
      return macResult.data
    } catch (e) {
      HiLogUtils.error(JSON.stringify(e))
      return new Uint8Array()
    }
  }
}