// -*- coding: utf-8 -*-
// Project    : Security
// File       : SecurityResult.ets
// Time       ：2024/6/19
// Author     ：ya dong
// Copyright © 2024 CL. All rights reserved.

import { util } from '@kit.ArkTS'
import { HiLogUtils } from './utils/log/HiLogUtils'

export class SecurityResult {
  private _data: Uint8Array
  code: number = 0

  constructor(initData: Uint8Array) {
    this._data = initData
    if (this._data && this._data.length > 0) {
      this.code = 100
    }
  }

  data(): Uint8Array {
    return this._data
  }

  utf8String(): string {
    if (this.code === 0) {
      return ''
    }
    try {
      return util.TextDecoder.create().decodeToString(this._data)
    } catch (e) {
      HiLogUtils.error(JSON.stringify(e))
      this.code = 0
      return ''
    }
  }

  hex(): string {
    if (this.code === 0) {
      return ''
    }
    return this.hexLower().toUpperCase()
  }

  hexLower(): string {
    if (this.code === 0) {
      return ''
    }
    return this._data.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '')
  }

  base64(): string {
    if (this.code === 0) {
      return ''
    }
    try {
      return new util.Base64Helper().encodeToStringSync(this._data)
    } catch (e) {
      HiLogUtils.error(JSON.stringify(e))
      this.code = 0
      return ''
    }
  }
}

