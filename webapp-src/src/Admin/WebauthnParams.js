import React, { Component } from 'react';
import i18next from 'i18next';

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
    
    if (props.mod.parameters["session-mandatory"] === undefined) {
      props.mod.parameters["session-mandatory"] = false;
    }
    
    if (props.mod.parameters.fmt === undefined) {
      props.mod.parameters.fmt = {
        "packed": true,
        "tpm": false,
        "android-key": false,
        "android-safetynet": true,
        "fido-u2f": true,
        "none": true
      };
    }
    
    if (props.mod.parameters["seed"] === undefined) {
      props.mod.parameters["seed"] = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    }
    
    if (props.mod.parameters["root-ca-list"] === undefined) {
      props.mod.parameters["root-ca-list"] = [];
    }
    
    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check,
      hasError: false,
      errorList: {},
      rootCaPath: ""
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.changeParam = this.changeParam.bind(this);
    this.checkParameters = this.checkParameters.bind(this);
    this.togglePubkey = this.togglePubkey.bind(this);
    this.changeSIParam = this.changeSIParam.bind(this);
    this.toggleSessionMandatory = this.toggleSessionMandatory.bind(this);
    this.generateSeed = this.generateSeed.bind(this);
    this.toggleForceFmtNone = this.toggleForceFmtNone.bind(this);
    this.handleChangeRootCaPath = this.handleChangeRootCaPath.bind(this);
    this.addRootCaPath = this.addRootCaPath.bind(this);
    this.deleteCaPath = this.deleteCaPath.bind(this);
    this.toggleFmt = this.toggleFmt.bind(this);
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
  
  toggleSessionMandatory(e) {
    var mod = this.state.mod;
    mod.parameters["session-mandatory"] = !mod.parameters["session-mandatory"];
    this.setState({mod: mod});
  }
  
  toggleForceFmtNone(e) {
    var mod = this.state.mod;
    mod.parameters["force-fmt-none"] = !mod.parameters["force-fmt-none"];
    this.setState({mod: mod});
  }
  
  toggleFmt(e, fmt) {
    var mod = this.state.mod;
    mod.parameters.fmt[fmt] = !mod.parameters.fmt[fmt];
    this.setState({mod: mod});
  }
  
  changeSIParam(e, param, value) {
    var mod = this.state.mod;
    mod.parameters[param] = value;
    this.setState({mod: mod});
  }
  
  generateSeed() {
    var mod = this.state.mod;
    mod.parameters["seed"] = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    this.setState({mod: mod});
  }
  
  handleChangeRootCaPath(e) {
    this.setState({rootCaPath: e.target.value});
  }
  
  addRootCaPath() {
    if (this.state.rootCaPath) {
      var mod = this.state.mod;
      mod.parameters["root-ca-list"].push(this.state.rootCaPath);
      this.setState({rootCaPath: "", mod: mod});
    }
  }
  
  deleteCaPath(e, index) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["root-ca-list"].splice(index, 1);
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
    if (!this.state.mod.parameters.fmt["packed"] && !this.state.mod.parameters.fmt["tpm"] && !this.state.mod.parameters.fmt["android-key"] && !this.state.mod.parameters.fmt["android-safetynet"] && !this.state.mod.parameters.fmt["fido-u2f"] && !this.state.mod.parameters.fmt["none"]) {
      hasError = true;
      errorList["fmt"] = i18next.t("admin.mod-webauthn-fmt-error")
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
    var listRootCaPath = [];
    this.state.mod.parameters["root-ca-list"].forEach((caPath, index) => {
      listRootCaPath.push(
        <div><a href="#" onClick={(e) => this.deleteCaPath(e, index)} key={index}><span className="badge badge-primary btn-icon-right">{caPath}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a></div>
      );
    });
    return (
      <div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-webauthn-session-mandatory-check">
                {i18next.t("admin.mod-webauthn-session-mandatory")}
              </label>
            </div>
            <div className="input-group-text">
              <input className="form-control" type="checkbox" value="" id="mod-webauthn-session-mandatory-check" checked={this.state.mod.parameters["session-mandatory"]} onChange={(e) => this.toggleSessionMandatory(e)}/>
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-webauthn-force-fmt-none">
                {i18next.t("admin.mod-webauthn-force-fmt-none")}
              </label>
            </div>
            <div className="input-group-text">
              <input className="form-control" type="checkbox" value="" id="mod-webauthn-force-fmt-none" checked={this.state.mod.parameters["force-fmt-none"]} onChange={(e) => this.toggleForceFmtNone(e)}/>
            </div>
          </div>
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-seed">{i18next.t("admin.mod-webauthn-seed")}</label>
          <div className="input-group mb-3">
            <input type="text" className={this.state.errorList["seed"]?"form-control is-invalid":"form-control"} id="mod-webauthn-seed" onChange={(e) => this.changeParam(e, "seed")} value={this.state.mod.parameters["seed"]} placeholder={i18next.t("admin.mod-webauthn-seed-ph")} disabled={this.state.mod.parameters["session-mandatory"]}/>
            <div className="input-group-append">
              <button className="btn btn-outline-secondary" type="button" title={i18next.t("admin.mod-webauthn-seed-generate")} onClick={this.generateSeed}>{i18next.t("admin.mod-webauthn-seed-generate")}</button>
            </div>
          </div>
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-challenge-length">{i18next.t("admin.mod-webauthn-challenge-length")}</label>
          <input type="number" min="0" step="1" className={this.state.errorList["challenge-length"]?"form-control is-invalid":"form-control"} id="mod-webauthn-challenge-length" onChange={(e) => this.changeParam(e, "challenge-length")} value={this.state.mod.parameters["challenge-length"]} placeholder={i18next.t("admin.mod-webauthn-challenge-length-ph")} />
          {this.state.errorList["challenge-length"]?<span className="error-input">{this.state.errorList["challenge-length"]}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-credential-expiration">{i18next.t("admin.mod-webauthn-credential-expiration")}</label>
          <input type="number" min="0" step="1" className={this.state.errorList["credential-expiration"]?"form-control is-invalid":"form-control"} id="mod-webauthn-credential-expiration" onChange={(e) => this.changeParam(e, "credential-expiration", true)} value={this.state.mod.parameters["credential-expiration"]} placeholder={i18next.t("admin.mod-webauthn-credential-expiration-ph")} />
          {this.state.errorList["credential-expiration"]?<span className="error-input">{this.state.errorList["credential-expiration"]}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-credential-assertion">{i18next.t("admin.mod-webauthn-credential-assertion")}</label>
          <input type="number" min="0" step="1" className={this.state.errorList["credential-assertion"]?"form-control is-invalid":"form-control"} id="mod-webauthn-credential-assertion" onChange={(e) => this.changeParam(e, "credential-assertion", true)} value={this.state.mod.parameters["credential-assertion"]} placeholder={i18next.t("admin.mod-webauthn-credential-assertion-ph")} />
          {this.state.errorList["credential-assertion"]?<span className="error-input">{this.state.errorList["credential-assertion"]}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-rp-origin">{i18next.t("admin.mod-webauthn-rp-origin")}</label>
          <input type="text" className={this.state.errorList["rp-origin"]?"form-control is-invalid":"form-control"} id="mod-webauthn-rp-origin" onChange={(e) => this.changeParam(e, "rp-origin")} value={this.state.mod.parameters["rp-origin"]} placeholder={i18next.t("admin.mod-webauthn-rp-origin-ph")} />
          {this.state.errorList["rp-origin"]?<span className="error-input">{this.state.errorList["rp-origin"]}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-webauthn-fmt-params">{i18next.t("admin.mod-webauthn-fmt-params")}</label>
          <ul>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-fmt-packed" checked={this.state.mod.parameters.fmt["packed"]} onChange={(e) => this.toggleFmt(e, "packed")}/>
              <label className="form-check-label" htmlFor="mod-webauthn-fmt-packed">
                {i18next.t("admin.mod-webauthn-fmt-packed-label")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-fmt-tpm" checked={this.state.mod.parameters.fmt["tpm"]} onChange={(e) => this.toggleFmt(e, "tpm")} disabled={true}/>
              <label className="form-check-label" htmlFor="mod-webauthn-fmt-tpm" title={i18next.t("admin.mod-webauthn-unsupported")}>
                {i18next.t("admin.mod-webauthn-fmt-tpm-label")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-fmt-android-key" checked={this.state.mod.parameters.fmt["android-key"]} onChange={(e) => this.toggleFmt(e, "android-key")} disabled={true}/>
              <label className="form-check-label" htmlFor="mod-webauthn-fmt-android-key" title={i18next.t("admin.mod-webauthn-unsupported")}>
                {i18next.t("admin.mod-webauthn-fmt-android-key-label")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-fmt-android-safetynet" checked={this.state.mod.parameters.fmt["android-safetynet"]} onChange={(e) => this.toggleFmt(e, "android-safetynet")}/>
              <label className="form-check-label" htmlFor="mod-webauthn-fmt-android-safetynet">
                {i18next.t("admin.mod-webauthn-fmt-android-safetynet-label")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-fmt-fido-u2f" checked={this.state.mod.parameters.fmt["fido-u2f"]} onChange={(e) => this.toggleFmt(e, "fido-u2f")}/>
              <label className="form-check-label" htmlFor="mod-webauthn-fmt-fido-u2f">
                {i18next.t("admin.mod-webauthn-fmt-fido-u2f-label")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-fmt-none" checked={this.state.mod.parameters.fmt["none"]} onChange={(e) => this.toggleFmt(e, "none")}/>
              <label className="form-check-label" htmlFor="mod-webauthn-fmt-none">
                {i18next.t("admin.mod-webauthn-fmt-none-label")}
              </label>
            </li>
          </ul>
          {this.state.errorList["fmt"]?<span className="error-input">{this.state.errorList["fmt"]}</span>:""}
        </div>
        <hr/>
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
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-rsa-sha256-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-257)>-1} onChange={(e) => this.togglePubkey(e, -257)} disabled={true}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-rsa-sha256-check" title={i18next.t("admin.mod-webauthn-unsupported")}>
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-rsa-sha256")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-rsa-sha384-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-258)>-1} onChange={(e) => this.togglePubkey(e, -258)} disabled={true}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-rsa-sha384-check" title={i18next.t("admin.mod-webauthn-unsupported")}>
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-rsa-sha384")}
              </label>
            </li>
            <li>
              <input className="form-check-input" type="checkbox" value="" id="mod-webauthn-pubKey-cred-params-rsa-sha512-check" checked={this.state.mod.parameters["pubKey-cred-params"].indexOf(-259)>-1} onChange={(e) => this.togglePubkey(e, -259)} disabled={true}/>
              <label className="form-check-label" htmlFor="mod-webauthn-pubKey-cred-params-rsa-sha512-check" title={i18next.t("admin.mod-webauthn-unsupported")}>
                {i18next.t("admin.mod-webauthn-pubKey-cred-params-label-rsa-sha512")}
              </label>
            </li>
          </ul>
          {this.state.errorList["pubKey-cred-params"]?<span className="error-input">{this.state.errorList["pubKey-cred-params"]}</span>:""}
        </div>
        <hr/>
        <div className="form-group">
          <label>{i18next.t("admin.mod-webauthn-root-ca-list")}</label>
        </div>
        <div className="form-group">
          <a href="https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt" className="badge badge-primary" target="_blank">{i18next.t("admin.mod-webauthn-root-ca-yubico-link")}</a>
        </div>
        <div className="form-group">
          <label htmlFor="webauthn-root-ca-path-input">{i18next.t("admin.mod-webauthn-root-ca-path")}</label>
          <div className="input-group">
            <input type="text" className="form-control" id="webauthn-root-ca-path-input" placeholder={i18next.t("admin.mod-webauthn-root-ca-path-ph")} onChange={this.handleChangeRootCaPath} value={this.state.rootCaPath}/>
            <div className="input-group-append">
              <button className="btn btn-outline-secondary" type="button" onClick={this.addRootCaPath} title={i18next.t("modal.list-add-title")}>
                <i className="fas fa-plus"></i>
              </button>
            </div>
          </div>
          <div className="btn-icon-right">{listRootCaPath}</div>
        </div>
        <hr/>
        <div className="form-group">
          <label>{i18next.t("admin.mod-webauthn-safetynet-integrity-params")}</label>
        </div>
        <div className="form-group">
          <a href="https://developer.android.com/training/safetynet/attestation#potential-integrity-verdicts" className="badge badge-primary" target="_blank">{i18next.t("admin.mod-webauthn-safetynet-integrity-link")}</a>
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
        <div className="form-group">
          <label htmlFor="mod-google-root-ca-r2">{i18next.t("admin.mod-webauthn-google-root-ca-r2")}</label>
          <a href="https://pki.goog/" className="badge badge-primary" target="_blank">{i18next.t("admin.mod-webauthn-google-root-ca-r2-download-link")}<i className="fas fa-external-link-alt btn-icon-right"></i></a>
          <input type="text" className="form-control" id="mod-google-root-ca-r2" onChange={(e) => this.changeParam(e, "google-root-ca-r2")} value={this.state.mod.parameters["google-root-ca-r2"]} placeholder={i18next.t("admin.mod-webauthn-google-root-ca-r2-ph")} />
        </div>
      </div>
    );
  }
}

export default WebauthnParams;
