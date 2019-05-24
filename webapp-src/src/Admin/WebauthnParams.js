import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class WebauthnParams extends Component {
  constructor(props) {
    super(props);
    
    if (!props.mod) {
      props.mod = {parameters: {}};
    }
    
    if (!props.mod.parameters["challenge-length"]) {
      props.mod.parameters["challenge-length"] = 64;
    }
    
    if (!props.mod.parameters["rp-origin"]) {
      props.mod.parameters["rp-origin"] = location.protocol + "//" + location.host;
    }
    
    if (!props.mod.parameters["pubKey-cred-params"]) {
      props.mod.parameters["pubKey-cred-params"] = [-7, -35, -36];
    }
    
    if (!props.mod.parameters["credential-expiration"]) {
      props.mod.parameters["credential-expiration"] = 120;
    }
    
    if (!props.mod.parameters["credential-assertion"]) {
      props.mod.parameters["credential-assertion"] = 120;
    }
    
    if (props.mod.parameters["ctsProfileMatch"] === undefined) {
      props.mod.parameters["ctsProfileMatch"] = 1;
    }
    
    if (props.mod.parameters["basicIntegrity"] === undefined) {
      props.mod.parameters["basicIntegrity"] = 1;
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
    this.checkParameters = this.checkParameters.bind(this);
    this.togglePubkey = this.togglePubkey.bind(this);
    this.changeSIParam = this.changeSIParam.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    
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
  
  togglePubkey(e, pubkey) {
    var mod = this.state.mod;
    if (mod.parameters["pubKey-cred-params"].indexOf(pubkey) > -1) {
      mod.parameters["pubKey-cred-params"].splice(mod.parameters["pubKey-cred-params"].indexOf(pubkey), 1);
    } else {
      mod.parameters["pubKey-cred-params"].push(pubkey);
    }
    this.setState({mod: mod});
  }
  
  changeSIParam(e, param, value) {
    var mod = this.state.mod;
    mod.parameters[param] = value;
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["challenge-length"]) {
      hasError = true;
      errorList["challenge-length"] = i18next.t("admin.mod-webauthn-challenge-length-error")
    }
    if (!this.state.mod.parameters["credential-expiration"]) {
      hasError = true;
      errorList["credential-expiration"] = i18next.t("admin.mod-webauthn-credential-expiration-error")
    }
    if (!this.state.mod.parameters["credential-expiration"]) {
      hasError = true;
      errorList["credential-expiration"] = i18next.t("admin.mod-webauthn-credential-expiration-error")
    }
    if (!this.state.mod.parameters["rp-origin"]) {
      hasError = true;
      errorList["rp-origin"] = i18next.t("admin.mod-webauthn-rp-origin-error")
    }
    if (!this.state.mod.parameters["pubKey-cred-params"].length) {
      hasError = true;
      errorList["pubKey-cred-params"] = i18next.t("admin.mod-webauthn-pubKey-cred-params-error")
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
          <label htmlFor="mod-webauthn-challenge-length">{i18next.t("admin.mod-webauthn-challenge-length")}</label>
          <input type="number" min="0" step="1" className={this.state.errorList["challenge-length"]?"form-control is-invalid":"form-control"} id="mod-webauthn-challenge-length" onChange={(e) => this.changeParam(e, "challenge-length")} value={this.state.mod.parameters["challenge-length"]} placeholder={i18next.t("admin.mod-webauthn-challenge-length-ph")} />
          {this.state.errorList["challenge-length"]?<span className="error-input">{i18next.t(this.state.errorList["challenge-length"])}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-credential-expiration">{i18next.t("admin.mod-webauthn-credential-expiration")}</label>
          <input type="number" min="0" step="1" className={this.state.errorList["credential-expiration"]?"form-control is-invalid":"form-control"} id="mod-webauthn-credential-expiration" onChange={(e) => this.changeParam(e, "credential-expiration", true)} value={this.state.mod.parameters["credential-expiration"]} placeholder={i18next.t("admin.mod-webauthn-credential-expiration-ph")} />
          {this.state.errorList["credential-expiration"]?<span className="error-input">{i18next.t(this.state.errorList["credential-expiration"])}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-credential-assertion">{i18next.t("admin.mod-webauthn-credential-assertion")}</label>
          <input type="number" min="0" step="1" className={this.state.errorList["credential-assertion"]?"form-control is-invalid":"form-control"} id="mod-webauthn-credential-assertion" onChange={(e) => this.changeParam(e, "credential-assertion", true)} value={this.state.mod.parameters["credential-assertion"]} placeholder={i18next.t("admin.mod-webauthn-credential-assertion-ph")} />
          {this.state.errorList["credential-assertion"]?<span className="error-input">{i18next.t(this.state.errorList["credential-assertion"])}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-rp-origin">{i18next.t("admin.mod-webauthn-rp-origin")}</label>
          <input type="text" className={this.state.errorList["rp-origin"]?"form-control is-invalid":"form-control"} id="mod-webauthn-rp-origin" onChange={(e) => this.changeParam(e, "rp-origin")} value={this.state.mod.parameters["rp-origin"]} placeholder={i18next.t("admin.mod-webauthn-rp-origin-ph")} />
          {this.state.errorList["rp-origin"]?<span className="error-input">{i18next.t(this.state.errorList["rp-origin"])}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-pubKey-cred-params">{i18next.t("admin.mod-webauthn-pubKey-cred-params")}</label>
          <ul>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-ecdsa-sha256-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-7)>-1} onChange={(e) => this.togglePubkey(e, -7)}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-ecdsa-sha256-check">
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-ecdsa-sha256")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-ecdsa-sha384-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-35)>-1} onChange={(e) => this.togglePubkey(e, -35)}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-ecdsa-sha384-check">
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-ecdsa-sha384")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-ecdsa-sha512-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-36)>-1} onChange={(e) => this.togglePubkey(e, -36)}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-ecdsa-sha512-check">
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-ecdsa-sha512")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-rsa-sha256-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-36)>-1} onChange={(e) => this.togglePubkey(e, -257)}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-rsa-sha256-check">
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-rsa-sha256")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-rsa-sha384-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-36)>-1} onChange={(e) => this.togglePubkey(e, -258)}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-rsa-sha384-check">
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-rsa-sha384")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-rsa-sha512-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-36)>-1} onChange={(e) => this.togglePubkey(e, -259)}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-rsa-sha512-check">
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-rsa-sha512")}
              </label>
            </li>
          </ul>
          {this.state.errorList["pubKey-cred-params"]?<span className="error-input">{i18next.t(this.state.errorList["pubKey-cred-params"])}</span>:""}
        </div>
        <hr/>
        <div className="form-group">
          <label>{i18next.t("admin.mod-webauthn-safetynet-integrity-params")}</label>
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-safetynet-integrity-ctsProfileMatch">{i18next.t("admin.mod-webauthn-safetynet-integrity-ctsProfileMatch")}</label>
          <div className="dropdown">
            <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-webauthn-safetynet-integrity-ctsProfileMatch" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              {i18next.t("admin.mod-webauthn-safetynet-integrity-" + this.state.mod.parameters["ctsProfileMatch"])}
            </button>
            <div className="dropdown-menu" aria-labelledby="mod-webauthn-safetynet-integrity-ctsProfileMatch">
              <a className={"dropdown-item"+(this.state.mod.parameters["ctsProfileMatch"]===-1?" active":"")} href="#" onClick={(e) => this.changeSIParam(e, "ctsProfileMatch", -1)}>{i18next.t("admin.mod-webauthn-safetynet-integrity--1")}</a>
              <a className={"dropdown-item"+(this.state.mod.parameters["ctsProfileMatch"]===0?" active":"")} href="#" onClick={(e) => this.changeSIParam(e, "ctsProfileMatch", 0)}>{i18next.t("admin.mod-webauthn-safetynet-integrity-0")}</a>
              <a className={"dropdown-item"+(this.state.mod.parameters["ctsProfileMatch"]===1?" active":"")} href="#" onClick={(e) => this.changeSIParam(e, "ctsProfileMatch", 1)}>{i18next.t("admin.mod-webauthn-safetynet-integrity-1")}</a>
            </div>
          </div>
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-safetynet-integrity-basicIntegrity">{i18next.t("admin.mod-webauthn-safetynet-integrity-basicIntegrity")}</label>
          <div className="dropdown">
            <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-webauthn-safetynet-integrity-basicIntegrity" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              {i18next.t("admin.mod-webauthn-safetynet-integrity-" + this.state.mod.parameters["basicIntegrity"])}
            </button>
            <div className="dropdown-menu" aria-labelledby="mod-webauthn-safetynet-integrity-basicIntegrity">
              <a className={"dropdown-item"+(this.state.mod.parameters["basicIntegrity"]===-1?" active":"")} href="#" onClick={(e) => this.changeSIParam(e, "basicIntegrity", -1)}>{i18next.t("admin.mod-webauthn-safetynet-integrity--1")}</a>
              <a className={"dropdown-item"+(this.state.mod.parameters["basicIntegrity"]===0?" active":"")} href="#" onClick={(e) => this.changeSIParam(e, "basicIntegrity", 0)}>{i18next.t("admin.mod-webauthn-safetynet-integrity-0")}</a>
              <a className={"dropdown-item"+(this.state.mod.parameters["basicIntegrity"]===1?" active":"")} href="#" onClick={(e) => this.changeSIParam(e, "basicIntegrity", 1)}>{i18next.t("admin.mod-webauthn-safetynet-integrity-1")}</a>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default WebauthnParams;
