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
  }
  
  componentWillReceiveProps(nextProps) {
    
    if (!nextProps.mod) {
      nextProps.mod = {parameters: {}};
    }
    
    if (!nextProps.mod.parameters["challenge-length"]) {
      nextProps.mod.parameters["challenge-length"] = 64;
    }
    
    if (!nextProps.mod.parameters["rp-origin"]) {
      nextProps.mod.parameters["rp-origin"] = location.protocol + "//" + location.host;
    }
    
    if (!nextProps.mod.parameters["pubKey-cred-params"]) {
      nextProps.mod.parameters["pubKey-cred-params"] = [-7, -35, -36];
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
  
  togglePubkey(e, pubkey) {
    var mod = this.state.mod;
    if (mod.parameters["pubKey-cred-params"].indexOf(pubkey) > -1) {
      mod.parameters["pubKey-cred-params"].splice(mod.parameters["pubKey-cred-params"].indexOf(pubkey), 1);
    } else {
      mod.parameters["pubKey-cred-params"].push(pubkey);
    }
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["challenge-length"]) {
      hasError = true;
      errorList["challenge-length"] = i18next.t("admin.mod-webauthn-challenge-length-error")
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
          <label htmlFor="mod-webauthn-rp-origin">{i18next.t("admin.mod-webauthn-rp-origin")}</label>
          <input type="text" className={this.state.errorList["rp-origin"]?"form-control is-invalid":"form-control"} id="mod-webauthn-rp-origin" onChange={(e) => this.changeParam(e, "rp-origin")} value={this.state.mod.parameters["rp-origin"]} placeholder={i18next.t("admin.mod-webauthn-rp-origin-ph")} />
          {this.state.errorList["rp-origin"]?<span className="error-input">{i18next.t(this.state.errorList["rp-origin"])}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-pubKey-cred-params">{i18next.t("admin.mod-webauthn-pubKey-cred-params")}</label>
          <div className="input-group">
            <div className="form-check">
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-ecdsa-sha256-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-7)>-1} onChange={(e) => this.togglePubkey(e, -7)}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-ecdsa-sha256-check">
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-ecdsa-sha256")}
              </label>
            </div>
            <div className="form-check">
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-ecdsa-sha384-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-35)>-1} onChange={(e) => this.togglePubkey(e, -35)}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-ecdsa-sha384-check">
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-ecdsa-sha384")}
              </label>
            </div>
            <div className="form-check">
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-ecdsa-sha512-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-36)>-1} onChange={(e) => this.togglePubkey(e, -36)}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-ecdsa-sha512-check">
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-ecdsa-sha512")}
              </label>
            </div>
          </div>
          {this.state.errorList["pubKey-cred-params"]?<span className="error-input">{i18next.t(this.state.errorList["pubKey-cred-params"])}</span>:""}
        </div>
      </div>
    );
  }
}

export default WebauthnParams;
