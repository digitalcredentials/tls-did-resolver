"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.TLSDIDResolverError = void 0;
var TLSDIDResolverError = /** @class */ (function (_super) {
    __extends(TLSDIDResolverError, _super);
    function TLSDIDResolverError(message, data) {
        var _this = _super.call(this, message) || this;
        _this.name = 'TLSDIDResolverError';
        _this.data = data;
        return _this;
    }
    TLSDIDResolverError.prototype.toString = function () {
        return this.message + " " + this.data.toString();
    };
    return TLSDIDResolverError;
}(Error));
exports.TLSDIDResolverError = TLSDIDResolverError;
//# sourceMappingURL=error.js.map