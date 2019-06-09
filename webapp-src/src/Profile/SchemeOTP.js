import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class SchemeOTP extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      module: props.module,
      name: props.name,
      profile: props.profile,
      myOtp: false,
      errorList: {}
    };
    
    this.getRegister = this.getRegister.bind(this);
    this.register = this.register.bind(this);
    this.changeParam = this.changeParam.bind(this);
    this.changeType = this.changeType.bind(this);
    this.generateSecret = this.generateSecret.bind(this);
    this.showQRCode = this.showQRCode.bind(this);
    
    this.getRegister();
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      module: nextProps.module,
      name: nextProps.name,
      profile: nextProps.profile,
    }, () => {
      this.getRegister();
    });
  }
  
  getRegister() {
    if (this.state.profile) {
      apiManager.glewlwydRequest("/profile/scheme/register/", "PUT", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name})
      .then((res) => {
        this.setState({myOtp: res});
      })
      .fail((err) => {
        if (err.status === 404) {
          this.setState({myOtp: {
            type: "NONE",
            secret: "", 
            moving_factor: 0,
            time_step_size: 30
          }});
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        }
      })
      .always(() => {
        this.showQRCode();
      });
    }
  }
  
  showQRCode() {
    var url = false;
    if (this.state.myOtp.issuer && this.state.profile.username && this.state.myOtp.secret && this.state.myOtp.digits) {
      if (this.state.myOtp.type === "HOTP" && this.state.myOtp.moving_factor) {
        url = "otpauth://hotp/" + this.state.myOtp.issuer + ":" + this.state.profile.username + "?" +
                  "issuer=" + encodeURI([location.protocol, '//', location.host].join('')) + "&" +
                  "secret=" + this.state.myOtp.secret + "&" +
                  "digits=" + this.state.myOtp.digits + "&" +
                  "algorithm=SHA1&" +
                  "counter=" + this.state.myOtp.moving_factor;
      } else if (this.state.myOtp.type === "TOTP" && this.state.myOtp.time_step_size) {
        url = "otpauth://totp/" + this.state.myOtp.issuer + ":" + this.state.profile.username + "?" +
                  "issuer=" + encodeURI([location.protocol, '//', location.host].join('')) + "&" +
                  "secret=" + this.state.myOtp.secret + "&" +
                  "digits=" + this.state.myOtp.digits + "&" +
                  "algorithm=SHA1&" +
                  "period=" + this.state.myOtp.time_step_size;
      }
    }
    $('#qrcode').empty();
    if (url) {
      $('#qrcode').qrcode(url);
    }
  }
  
  changeParam(e, param, number) {
    var myOtp = this.state.myOtp;
    if (number) {
      myOtp[param] = parseInt(e.target.value);
    } else {
      myOtp[param] = e.target.value;
    }
    this.setState({myOtp: myOtp}, () => {
      this.showQRCode();
    });
  }
  
  changeType(e, type) {
    e.preventDefault();
    var myOtp = this.state.myOtp;
    myOtp.type = type;
    this.setState({myOtp: myOtp}, () => {
      this.showQRCode();
    });
  }
  
  generateSecret() {
    apiManager.glewlwydRequest("/profile/scheme/register/", "POST", 
      {
        username: this.state.profile.username, 
        scheme_type: this.state.module, 
        scheme_name: this.state.name,
        value: {
          "generate-secret": true
        }
      })
    .then((res) => {
      var myOtp = this.state.myOtp;
      myOtp.secret = res.secret;
      this.setState({myOtp: myOtp}, () => {
        this.showQRCode();
      });
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
  }
  
  register() {
    var errorList = {}, hasError = false;
    if (this.state.myOtp.type !== "NONE") {
      if (!this.state.myOtp.secret) {
        errorList.secret = i18next.t("profile.scheme-otp-secret-error");
        hasError = true;
      }
      if (this.state.myOtp.type === "HOTP") {
        if (this.state.myOtp.moving_factor === "" || this.state.myOtp.moving_factor === undefined) {
          errorList.moving_factor = i18next.t("profile.scheme-otp-moving_factor-error");
          hasError = true;
        }
      } else if (this.state.myOtp.type === "TOTP") {
        if (this.state.myOtp.time_step_size === "" || this.state.myOtp.time_step_size === undefined) {
          errorList.time_step_size = i18next.t("profile.scheme-otp-time_step_size-error");
          hasError = true;
        }
        if (this.state.myOtp.start_offset === "") {
          errorList.start_offset = i18next.t("profile.scheme-otp-start_offset-error");
          hasError = true;
        }
      }
    }
    this.setState({errorList: errorList}, () => {
      if (!hasError) {
        apiManager.glewlwydRequest("/profile/scheme/register/", "POST", 
          {
            username: this.state.profile.username, 
            scheme_type: this.state.module, 
            scheme_name: this.state.name,
            value: this.state.myOtp
          })
        .then((res) => {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.scheme-otp-save-ok")});
          this.getRegister();
        })
        .fail((err) => {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-otp-save-error")});
        });
      }
    });
  }
  
	render() {
    var jsxHOTP, jsxTOTP, secretJsx;
    secretJsx = 
      <div className="row">
        <div className="col-md-12">
          <div className="input-group input-group-sm mb-3">
            <div className="input-group-prepend">
              <span className="input-group-text">{i18next.t("profile.scheme-otp-secret")}</span>
            </div>
            <input type="text" maxLength="128" className={!!this.state.errorList.secret?"form-control is-invalid":"form-control"} id="scheme-otp-secret" onChange={(e) => this.changeParam(e, "secret")} value={this.state.myOtp.secret} placeholder={i18next.t("profile.scheme-otp-secret-ph")} />
            <div className="input-group-append">
              <button className="btn btn-outline-secondary" type="button" onClick={this.generateSecret}>{i18next.t("profile.scheme-otp-generate-secret")}</button>
            </div>
            {!!this.state.errorList.secret?<span className="error-input">{i18next.t(this.state.errorList.secret)}</span>:""}
          </div>
        </div>
      </div>
    if (this.state.myOtp.type === "HOTP") {
      jsxHOTP = <div>
        {secretJsx}
        <div className="row">
          <div className="col-md-12">
            <div className="input-group input-group-sm mb-3">
              <div className="input-group-prepend">
                <span className="input-group-text">{i18next.t("profile.scheme-otp-moving_factor")}</span>
              </div>
              <input type="number" min="0" step="1" className={!!this.state.errorList.moving_factor?"form-control is-invalid":"form-control"} id="scheme-otp-moving_factor" onChange={(e) => this.changeParam(e, "moving_factor", 1)} value={this.state.myOtp.moving_factor} placeholder={i18next.t("profile.scheme-otp-moving_factor-ph")} />
              {!!this.state.errorList.moving_factor?<span className="error-input">{i18next.t(this.state.errorList.moving_factor)}</span>:""}
            </div>
          </div>
        </div>
      </div>
    } else if (this.state.myOtp.type === "TOTP") {
      jsxTOTP = <div>
        {secretJsx}
        <div className="row">
          <div className="col-md-12">
            <div className="input-group input-group-sm mb-3">
              <div className="input-group-prepend">
                <span className="input-group-text">{i18next.t("profile.scheme-otp-time_step_size")}</span>
              </div>
              <input type="number" min="0" step="1" className={!!this.state.errorList.time_step_size?"form-control is-invalid":"form-control"} id="scheme-otp-time_step_size" onChange={(e) => this.changeParam(e, "time_step_size", 1)} value={this.state.myOtp.time_step_size} placeholder={i18next.t("profile.scheme-otp-time_step_size-ph")} />
              {!!this.state.errorList.time_step_size?<span className="error-input">{i18next.t(this.state.errorList.time_step_size)}</span>:""}
            </div>
          </div>
        </div>
      </div>
    }

    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.scheme-otp-title")}</h4>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <div className="input-group input-group-sm mb-3">
              <div className="input-group-prepend">
                <span className="input-group-text">{i18next.t("profile.scheme-otp-type")}</span>
              </div>
              <div className="dropdown">
                <button className="btn btn-secondary dropdown-toggle" type="button" id="scheme-otp-type" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                  {i18next.t("profile.scheme-otp-type-" + this.state.myOtp.type)}
                </button>
                <div className="dropdown-menu" aria-labelledby="scheme-otp-type">
                  <a className={"dropdown-item"+(this.state.myOtp.type==="TOTP"?" active":"")} href="#" onClick={(e) => this.changeType(e, "TOTP")}>{i18next.t("profile.scheme-otp-type-TOTP")}</a>
                  <a className={"dropdown-item"+(this.state.myOtp.type==="HOTP"?" active":"")} href="#" onClick={(e) => this.changeType(e, "HOTP")}>{i18next.t("profile.scheme-otp-type-HOTP")}</a>
                  <a className={"dropdown-item"+(this.state.myOtp.type==="NONE"?" active":"")} href="#" onClick={(e) => this.changeType(e, "NONE")}>{i18next.t("profile.scheme-otp-type-NONE")}</a>
                </div>
              </div>
            </div>
          </div>
        </div>
        {jsxHOTP}
        {jsxTOTP}
        <div className="row">
          <div className="col-md-12">
            <div id="qrcode"></div>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <hr/>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <div className="btn-group" role="group">
              <button type="button" className="btn btn-primary" onClick={(e) => this.register(e)}>{i18next.t("profile.scheme-otp-save")}</button>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default SchemeOTP;
