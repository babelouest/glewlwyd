import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';

class OTPParams extends Component {
  constructor(props) {
    super(props);
    
    if (!props.mod) {
      props.mod = {parameters: {}};
    }
    
    if (!props.mod.parameters["secret-minimum-size"]) {
      props.mod.parameters["secret-minimum-size"] = 16;
    }

    if (!props.mod.parameters["issuer"]) {
      props.mod.parameters["issuer"] = location.host;
    }

    if (props.mod.parameters["otp-length"] === undefined) {
      props.mod.parameters["otp-length"] = 6;
    }

    if (props.mod.parameters["hotp-allow"] === undefined) {
      props.mod.parameters["hotp-allow"] = true;
    }

    if (props.mod.parameters["hotp-window"] === undefined) {
      props.mod.parameters["hotp-window"] = 0;
    }

    if (props.mod.parameters["totp-allow"] === undefined) {
      props.mod.parameters["totp-allow"] = true;
    }

    if (props.mod.parameters["totp-window"] === undefined) {
      props.mod.parameters["totp-window"] = 30;
    }

    if (props.mod.parameters["totp-start-offset"] === undefined) {
      props.mod.parameters["totp-start-offset"] = 0;
    }

    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check,
      hasError: false,
      errorList: {}
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.changeParam = this.changeParam.bind(this);
    this.toggleParam = this.toggleParam.bind(this);
    this.checkParameters = this.checkParameters.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    
    if (!nextProps.mod) {
      nextProps.mod = {parameters: {}};
    }
    
    if (!nextProps.mod.parameters["issuer"]) {
      nextProps.mod.parameters["issuer"] = location.host;
    }

    if (nextProps.mod.parameters["secret-minimum-size"] === undefined) {
      nextProps.mod.parameters["secret-minimum-size"] = 16;
    }

    if (nextProps.mod.parameters["otp-length"] === undefined) {
      nextProps.mod.parameters["otp-length"] = 6;
    }

    if (nextProps.mod.parameters["hotp-allow"] === undefined) {
      nextProps.mod.parameters["hotp-allow"] = true;
    }

    if (nextProps.mod.parameters["hotp-window"] === undefined) {
      nextProps.mod.parameters["hotp-window"] = 0;
    }

    if (nextProps.mod.parameters["totp-allow"] === undefined) {
      nextProps.mod.parameters["totp-allow"] = true;
    }

    if (nextProps.mod.parameters["totp-window"] === undefined) {
      nextProps.mod.parameters["totp-window"] = 30;
    }

    if (nextProps.mod.parameters["totp-start-offset"] === undefined) {
      nextProps.mod.parameters["totp-start-offset"] = 0;
    }

    this.setState({
      config: nextProps.config,
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check,
      hasError: false
    }, () => {
      if (this.state.check) {
        this.checkParameters();
      }
    });
  }
  
  changeParam(e, param, number) {
    var mod = this.state.mod;
    if (number) {
      mod.parameters[param] = parseInt(e.target.value);
    } else {
      mod.parameters[param] = e.target.value;
    }
    this.setState({mod: mod});
  }
  
  toggleParam(param) {
    var mod = this.state.mod;
    mod.parameters[param] = !mod.parameters[param];
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["issuer"]) {
      hasError = true;
      errorList["issuer"] = i18next.t("admin.mod-otp-issuer-error")
    }
    if (!this.state.mod.parameters["secret-minimum-size"]) {
      hasError = true;
      errorList["secret-minimum-size"] = i18next.t("admin.mod-otp-secret-minimum-size-error")
    }
    if (!this.state.mod.parameters["otp-length"]) {
      hasError = true;
      errorList["otp-length"] = i18next.t("admin.mod-otp-otp-length-error")
    }
    if (this.state.mod.parameters["hotp-allow"] && this.state.mod.parameters["hotp-window"] === "") {
      hasError = true;
      errorList["hotp-window"] = i18next.t("admin.mod-otp-hotp-window-error")
    }
    if (this.state.mod.parameters["totp-allow"] && this.state.mod.parameters["totp-window"] === "") {
      hasError = true;
      errorList["totp-window"] = i18next.t("admin.mod-otp-totp-window-error")
    }
    if (this.state.mod.parameters["totp-allow"] && this.state.mod.parameters["totp-start-offset"] === "") {
      hasError = true;
      errorList["totp-start-offset"] = i18next.t("admin.mod-otp-totp-start-offset-error")
    }
    if (!hasError) {
      this.setState({errorList: {}}, () => {
        messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
      });
    } else {
      this.setState({errorList: errorList});
    }
  }
  
  render() {
    return (
      <div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-otp-issuer">{i18next.t("admin.mod-otp-issuer")}</label>
            </div>
            <input type="text" className={this.state.errorList["issuer"]?"form-control is-invalid":"form-control"} id="mod-otp-issuer" onChange={(e) => this.changeParam(e, "issuer")} value={this.state.mod.parameters["issuer"]} placeholder={i18next.t("admin.mod-otp-issuer-ph")} />
          </div>
          {this.state.errorList["issuer"]?<span className="error-input">{this.state.errorList["issuer"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-otp-secret-minimum-size">{i18next.t("admin.mod-otp-secret-minimum-size")}</label>
            </div>
            <input type="number" min="0" max="128" step="1" className={this.state.errorList["secret-minimum-size"]?"form-control is-invalid":"form-control"} id="mod-otp-secret-minimum-size" onChange={(e) => this.changeParam(e, "secret-minimum-size", 1)} value={this.state.mod.parameters["secret-minimum-size"]} placeholder={i18next.t("admin.mod-otp-secret-minimum-size-ph")} />
          </div>
          {this.state.errorList["secret-minimum-size"]?<span className="error-input">{this.state.errorList["secret-minimum-size"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-otp-otp-length">{i18next.t("admin.mod-otp-otp-length")}</label>
            </div>
            <input type="number" min="6" max="8" step="1" className={this.state.errorList["otp-length"]?"form-control is-invalid":"form-control"} id="mod-otp-otp-length" onChange={(e) => this.changeParam(e, "otp-length", 1)} value={this.state.mod.parameters["otp-length"]} placeholder={i18next.t("admin.mod-otp-otp-length-ph")} />
          </div>
          {this.state.errorList["otp-length"]?<span className="error-input">{this.state.errorList["otp-length"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-otp-hotp-allow">{i18next.t("admin.mod-otp-hotp-allow")}</label>
            </div>
            <div className="input-group-text">
              <input type="checkbox" className="form-control" id="mod-otp-hotp-allow" onChange={(e) => this.toggleParam("hotp-allow")} checked={this.state.mod.parameters["hotp-allow"]} />
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-otp-hotp-window">{i18next.t("admin.mod-otp-hotp-window")}</label>
            </div>
            <input type="number" min="0" max="16" step="1" className={this.state.errorList["hotp-window"]?"form-control is-invalid":"form-control"} id="mod-otp-hotp-window" onChange={(e) => this.changeParam(e, "hotp-window", 1)} value={this.state.mod.parameters["hotp-window"]} placeholder={i18next.t("admin.mod-otp-hotp-window-ph")} disabled={!this.state.mod.parameters["hotp-allow"]}/>
          </div>
          {this.state.errorList["hotp-window"]?<span className="error-input">{this.state.errorList["hotp-window"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-otp-totp-allow">{i18next.t("admin.mod-otp-totp-allow")}</label>
            </div>
            <div className="input-group-text">
              <input type="checkbox" className="form-control" id="mod-otp-totp-allow" onChange={(e) => this.toggleParam("totp-allow")} checked={this.state.mod.parameters["totp-allow"]} />
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-otp-totp-window">{i18next.t("admin.mod-otp-totp-window")}</label>
            </div>
            <input type="number" min="0" max="16" step="1" className={this.state.errorList["totp-window"]?"form-control is-invalid":"form-control"} id="mod-otp-totp-window" onChange={(e) => this.changeParam(e, "totp-window", 1)} value={this.state.mod.parameters["totp-window"]} placeholder={i18next.t("admin.mod-otp-totp-window-ph")} disabled={!this.state.mod.parameters["totp-allow"]}/>
          </div>
          {this.state.errorList["totp-window"]?<span className="error-input">{this.state.errorList["totp-window"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-otp-totp-start-offset">{i18next.t("admin.mod-otp-totp-start-offset")}</label>
            </div>
            <input type="number" min="0" max="16" step="1" className={this.state.errorList["totp-start-offset"]?"form-control is-invalid":"form-control"} id="mod-otp-totp-start-offset" onChange={(e) => this.changeParam(e, "totp-window", 1)} value={this.state.mod.parameters["totp-window"]} placeholder={i18next.t("admin.mod-otp-totp-start-offset-ph")} disabled={!this.state.mod.parameters["totp-allow"]}/>
          </div>
          {this.state.errorList["totp-start-offset"]?<span className="error-input">{this.state.errorList["totp-start-offset"]}</span>:""}
        </div>
      </div>
    );
  }
}

export default OTPParams;
