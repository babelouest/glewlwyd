!function(e,t){if("object"==typeof exports&&"object"==typeof module)module.exports=t();else if("function"==typeof define&&define.amd)define([],t);else{var n=t();for(var r in n)("object"==typeof exports?exports:e)[r]=n[r]}}(window,(function(){return function(e){function t(t){for(var r,i,c=t[0],s=t[1],l=t[2],f=0,p=[];f<c.length;f++)i=c[f],Object.prototype.hasOwnProperty.call(o,i)&&o[i]&&p.push(o[i][0]),o[i]=0;for(r in s)Object.prototype.hasOwnProperty.call(s,r)&&(e[r]=s[r]);for(u&&u(t);p.length;)p.shift()();return a.push.apply(a,l||[]),n()}function n(){for(var e,t=0;t<a.length;t++){for(var n=a[t],r=!0,c=1;c<n.length;c++){var s=n[c];0!==o[s]&&(r=!1)}r&&(a.splice(t--,1),e=i(i.s=n[0]))}return e}var r={},o={2:0},a=[];function i(t){if(r[t])return r[t].exports;var n=r[t]={i:t,l:!1,exports:{}};return e[t].call(n.exports,n,n.exports,i),n.l=!0,n.exports}i.m=e,i.c=r,i.d=function(e,t,n){i.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:n})},i.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},i.t=function(e,t){if(1&t&&(e=i(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var n=Object.create(null);if(i.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var r in e)i.d(n,r,function(t){return e[t]}.bind(null,r));return n},i.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return i.d(t,"a",t),t},i.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},i.p="";var c=window.webpackJsonp=window.webpackJsonp||[],s=c.push.bind(c);c.push=t,c=c.slice();for(var l=0;l<c.length;l++)t(c[l]);var u=s;return a.push([22,0]),n()}({2:function(e,t,n){"use strict";function r(e,t){for(var n=0;n<t.length;n++){var r=t[n];r.enumerable=r.enumerable||!1,r.configurable=!0,"value"in r&&(r.writable=!0),Object.defineProperty(e,r.key,r)}}var o=new(function(){function e(){!function(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}(this,e),this.subscriberList={}}var t,n;return t=e,(n=[{key:"subscribe",value:function(e,t){this.subscriberList[e]=t}},{key:"sendMessage",value:function(e,t){if(Array.isArray(e)||(e=[e]),"broadcast"===e[0])this.subscriberList.forEach((function(e,n){e({type:"broadcast",message:t})}));else for(var n in this.subscriberList)0<=e.indexOf(n)&&this.subscriberList[n](t)}}])&&r(t.prototype,n),e}());t.a=o},22:function(e,t,n){"use strict";n.r(t);var r=n(0),o=n.n(r),a=n(7),i=n.n(a),c=n(1),s=n(9),l=n(10),u=n(3);function f(e){return(f="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e})(e)}function p(e,t){for(var n=0;n<t.length;n++){var r=t[n];r.enumerable=r.enumerable||!1,r.configurable=!0,"value"in r&&(r.writable=!0),Object.defineProperty(e,r.key,r)}}function d(e,t){return(d=Object.setPrototypeOf||function(e,t){return e.__proto__=t,e})(e,t)}function m(e){if(void 0===e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return e}function y(e){return(y=Object.setPrototypeOf?Object.getPrototypeOf:function(e){return e.__proto__||Object.getPrototypeOf(e)})(e)}n(4);var h=function(){!function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function");e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,writable:!0,configurable:!0}}),t&&d(e,t)}(a,r.Component);var e,t,n=function(e){var t=function(){if("undefined"==typeof Reflect||!Reflect.construct)return!1;if(Reflect.construct.sham)return!1;if("function"==typeof Proxy)return!0;try{return Date.prototype.toString.call(Reflect.construct(Date,[],(function(){}))),!0}catch(e){return!1}}();return function(){var n,r,o,a=y(e);return r=this,!(o=t?(n=y(this).constructor,Reflect.construct(a,arguments,n)):a.apply(this,arguments))||"object"!==f(o)&&"function"!=typeof o?m(r):o}}(a);function a(e){var t;return function(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}(this,a),(t=n.call(this,e)).state={config:e.config,errorAuthentication:!1,unknownError:t.parseState(e.config.params.state,e.config),gotoProfile:!1,gotoLogin:!1},t.gotoLogin=t.gotoLogin.bind(m(t)),t.gotoProfile=t.gotoProfile.bind(m(t)),t}return e=a,(t=[{key:"Base64DecodeUrl",value:function(e){return e.length%4==2?e+="==":e.length%4==3&&(e+="="),e.replace(/-/g,"+").replace(/_/g,"/")}},{key:"parseState",value:function(e,t){var n=this,r=!1;if(e){var o,a=!1,i=!1;try{a=JSON.parse(atob(this.Base64DecodeUrl(e)))}catch(e){i=!0}i?r=!0:"registration"===a.type?(o={scheme_name:a.module,scheme_type:"oauth2",username:a.username,value:{action:"callback",provider:a.provider,state:e,redirect_to:window.location.href}},$.ajax({method:"POST",url:a.register_url+"/profile/scheme/register/",data:JSON.stringify(o),contentType:"application/json; charset=utf-8"}).then((function(){n.setState({stateDecoded:a},(function(){var e=a.complete_url;-1<e.indexOf("?")?e+="&":e+="?",e+="scheme_name="+a.module+"&provider="+a.provider,window.location.href=e}))})).fail((function(e){401===e.status?n.setState({stateDecoded:a,errorAuthentication:!0,gotoProfile:!0}):n.setState({stateDecoded:a,unknownError:!0,gotoProfile:!0})}))):"authentication"===a.type?(o={scheme_name:a.module,scheme_type:"oauth2",username:a.username,value:{provider:a.provider,state:e,redirect_to:window.location.href}},$.ajax({method:"POST",url:t.GlewlwydUrl+"/"+t.api_prefix+"/auth/",data:JSON.stringify(o),contentType:"application/json; charset=utf-8"}).then((function(){n.setState({stateDecoded:a},(function(){window.location.href=a.callback_url}))})).fail((function(e){401===e.status?n.setState({stateDecoded:a,errorAuthentication:!0,gotoLogin:!0}):n.setState({stateDecoded:a,unknownError:!0,gotoLogin:!0})}))):r=!0}else r=!0;return r}},{key:"gotoLogin",value:function(){window.location.href=this.state.stateDecoded.callback_url}},{key:"gotoProfile",value:function(){var e;this.state.stateDecoded&&this.state.stateDecoded.complete_url?(-1<(e=this.state.stateDecoded.complete_url).indexOf("?")?e+="&":e+="?",e+="scheme_name="+this.state.stateDecoded.module+"&provider="+this.state.stateDecoded.provider,window.location.href=e):window.location.href=this.state.config.ProfileUrl}},{key:"render",value:function(){if(this.state.config){if(this.state.errorAuthentication||this.state.unknownError){var e=this.state.gotoLogin?o.a.createElement("button",{type:"button",className:"btn btn-primary",id:"buttonBack",onClick:this.gotoLogin},c.a.t("callback.button-login")):o.a.createElement("button",{type:"button",className:"btn btn-primary",id:"buttonBack",onClick:this.gotoProfile},c.a.t("callback.button-profile"));return o.a.createElement("div",{className:"perfect-centering"},o.a.createElement("div",{className:"alert alert-danger"},o.a.createElement("h3",null,this.state.errorAuthentication?c.a.t("callback.authentication-error"):c.a.t("callback.unknown-error"))),o.a.createElement("div",{className:"row justify-content-md-center"},e))}return o.a.createElement("div",{className:"perfect-centering"},o.a.createElement("div",{className:"alert alert-info"},o.a.createElement("h3",null,c.a.t("callback.authentication-success"))))}return o.a.createElement("div",{"aria-live":"polite","aria-atomic":"true",style:{position:"relative",minHeight:"200px"}},o.a.createElement("div",{className:"card center",id:"userCard",tabIndex:"-1",role:"dialog",style:{marginTop:"20px",marginBottom:"20px"}},o.a.createElement("div",{className:"card-header"},o.a.createElement("h4",null,o.a.createElement("span",{className:"badge badge-danger"},c.a.t("error-api-connect"))))))}}])&&p(e.prototype,t),a}();function b(e,t){(null==t||t>e.length)&&(t=e.length);for(var n=0,r=new Array(t);n<t;n++)r[n]=e[n];return r}function g(e){if(e){var t=e.split("&"),n={};return t.map((function(e){var t=function(e,t){return function(e){if(Array.isArray(e))return e}(e)||function(e,t){if("undefined"!=typeof Symbol&&Symbol.iterator in Object(e)){var n=[],r=!0,o=!1,a=void 0;try{for(var i,c=e[Symbol.iterator]();!(r=(i=c.next()).done)&&(n.push(i.value),!t||n.length!==t);r=!0);}catch(e){o=!0,a=e}finally{try{r||null==c.return||c.return()}finally{if(o)throw a}}return n}}(e,t)||function(e,t){if(e){if("string"==typeof e)return b(e,t);var n=Object.prototype.toString.call(e).slice(8,-1);return"Object"===n&&e.constructor&&(n=e.constructor.name),"Map"===n||"Set"===n?Array.from(e):"Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)?b(e,t):void 0}}(e,t)||function(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}(e.split("="),2),r=t[0],o=t[1];n[r]=decodeURIComponent(o)})),n}return{}}var v={fallbackLng:"en",ns:["translations"],defaultNS:"translations",backend:{loadPath:"locales/{{lng}}/{{ns}}.json"}};g(window.location.href.split("?")[1]).ui_locales&&(v.lng=g(window.location.href.split("?")[1]).ui_locales.split(" ")[0]);try{c.a.use(s.a).use(l.a).init(v).then((function(){u.a.request("config.json").then((function(e){e.lang||(e.lang=["en","fr","nl"]),u.a.request(e.GlewlwydUrl+"config/").then((function(t){u.a.setConfig(e.GlewlwydUrl+t.api_prefix);var n=Object.assign({params:{state:g(window.location.href.split("?")[1]).state||g(window.location.hash.substring(1)).state||!1}},e,t);i.a.render(o.a.createElement(h,{config:n}),document.getElementById("root"))})).fail((function(e){i.a.render(o.a.createElement(h,{config:!1}),document.getElementById("root"))}))}))}))}catch(e){$("#root").html('<div class="alert alert-danger" role="alert"><i class="fas fa-exclamation-triangle"></i><span class="btn-icon-right">You must use a browser compatible with Glewlwyd SSO</span></div>')}},3:function(e,t,n){"use strict";var r=n(2);function o(e,t){for(var n=0;n<t.length;n++){var r=t[n];r.enumerable=r.enumerable||!1,r.configurable=!0,"value"in r&&(r.writable=!0),Object.defineProperty(e,r.key,r)}}var a=new(function(){function e(){!function(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}(this,e),this.GlewlwydApiPrefix="",this.GlewlwydApiPrefixSub=""}var t,n;return t=e,(n=[{key:"setConfig",value:function(e){this.GlewlwydApiPrefix=e}},{key:"getConfig",value:function(){return this.GlewlwydApiPrefix}},{key:"setConfigSub",value:function(e){this.GlewlwydApiPrefixSub=e}},{key:"getConfigSub",value:function(){return this.GlewlwydApiPrefixSub}},{key:"request",value:function(e,t,n){var r=1<arguments.length&&void 0!==t?t:"GET",o=2<arguments.length&&void 0!==n&&n;return o&&"GET"!==r?$.ajax({method:r,url:e,data:JSON.stringify(o),contentType:"application/json; charset=utf-8"}):$.ajax({method:r,url:e})}},{key:"glewlwydRequest",value:function(e,t,n,o){var a=1<arguments.length&&void 0!==t?t:"GET",i=2<arguments.length&&void 0!==n&&n,c=3<arguments.length&&void 0!==o&&o;return this.request(this.GlewlwydApiPrefix+e,a,i).fail((function(e){c&&401===e.status&&r.a.sendMessage("App",{type:"loggedIn",message:!1})}))}},{key:"glewlwydRequestSub",value:function(e,t,n){var r=1<arguments.length&&void 0!==t?t:"GET",o=2<arguments.length&&void 0!==n&&n;return this.request(this.GlewlwydApiPrefixSub+e,r,o)}}])&&o(t.prototype,n),e}());t.a=a},4:function(e,t,n){"use strict";var r=n(0),o=n.n(r),a=n(2);function i(e){return(i="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e})(e)}function c(e,t){for(var n=0;n<t.length;n++){var r=t[n];r.enumerable=r.enumerable||!1,r.configurable=!0,"value"in r&&(r.writable=!0),Object.defineProperty(e,r.key,r)}}function s(e,t){return(s=Object.setPrototypeOf||function(e,t){return e.__proto__=t,e})(e,t)}function l(e){if(void 0===e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return e}function u(e){return(u=Object.setPrototypeOf?Object.getPrototypeOf:function(e){return e.__proto__||Object.getPrototypeOf(e)})(e)}var f=function(){!function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function");e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,writable:!0,configurable:!0}}),t&&s(e,t)}(f,r.Component);var e,t,n=function(e){var t=function(){if("undefined"==typeof Reflect||!Reflect.construct)return!1;if(Reflect.construct.sham)return!1;if("function"==typeof Proxy)return!0;try{return Date.prototype.toString.call(Reflect.construct(Date,[],(function(){}))),!0}catch(e){return!1}}();return function(){var n,r,o,a=u(e);return r=this,!(o=t?(n=u(this).constructor,Reflect.construct(a,arguments,n)):a.apply(this,arguments))||"object"!==i(o)&&"function"!=typeof o?l(r):o}}(f);function f(e){var t;return function(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}(this,f),(t=n.call(this,e)).state={message:[],counter:0},a.a.subscribe("Notification",(function(e){var n;e.type&&((n=t.state.message).push({type:e.type,message:e.message,id:t.state.counter}),t.setState({message:n,counter:t.state.counter+1},(function(){t.timeoutClose(t.state.counter-1)})))})),t.close=t.close.bind(l(t)),t.timeoutClose=t.timeoutClose.bind(l(t)),t}return e=f,(t=[{key:"timeoutClose",value:function(e){var t=this;setTimeout((function(){t.close(e)}),5e3)}},{key:"close",value:function(e){var t=this,n=this.state.message;n.forEach((function(r,o){r.id===e&&(n.splice(o,1),t.setState({message:n}))}))}},{key:"render",value:function(){var e=this,t=[];return this.state.message.forEach((function(n,r){var a="success"===n.type?o.a.createElement("strong",{className:"mr-auto"},o.a.createElement("span",{className:"badge badge-success btn-icon"},o.a.createElement("i",{className:"fas fa-check-circle"})),"Glewlwyd"):"danger"===n.type?o.a.createElement("strong",{className:"mr-auto"},o.a.createElement("span",{className:"badge badge-danger btn-icon"},o.a.createElement("i",{className:"fas fa-exclamation-circle"})),"Glewlwyd"):"warning"===n.type?o.a.createElement("strong",{className:"mr-auto"},o.a.createElement("span",{className:"badge badge-warning btn-icon"},o.a.createElement("i",{className:"fas fa-exclamation-circle"})),"Glewlwyd"):o.a.createElement("strong",{className:"mr-auto"},o.a.createElement("span",{className:"badge badge-info btn-icon"},o.a.createElement("i",{className:"fas fa-info-circle"})),"Glewlwyd");t.push(o.a.createElement("div",{className:"toast-container",style:{top:85+90*r,right:5},key:r},o.a.createElement("div",{className:"toast",role:"alert","aria-live":"assertive","aria-atomic":"true"},o.a.createElement("div",{className:"toast-header"},a,o.a.createElement("button",{type:"button",className:"ml-2 mb-1 close","data-dismiss":"toast","aria-label":"Close",onClick:function(){return e.close(n.id)}},o.a.createElement("span",{"aria-hidden":"true"},"×"))),o.a.createElement("div",{className:"toast-body"},n.message))))})),o.a.createElement("div",null,t)}}])&&c(e.prototype,t),f}();t.a=f}})}));