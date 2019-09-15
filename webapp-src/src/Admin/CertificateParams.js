import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class CertificateParams extends Component {
  constructor(props) {
    super(props);
    
    if (props.mod===undefined) props.mod = {};
    if (props.mod.parameters===undefined) props.mod.parameters = {};
    if (props.mod.parameters["cert-source"]===undefined) props.mod.parameters["cert-source"]="TLS";
    if (props.mod.parameters["header-name"]===undefined) props.mod.parameters["header-name"]="SSL_CLIENT_CERT";
    if (props.mod.parameters["use-scheme-storage"]===undefined) props.mod.parameters["use-scheme-storage"]=false;
    if (props.mod.parameters["user-certificate-property"]===undefined) props.mod.parameters["user-certificate-property"]="";
    if (props.mod.parameters["user-certificate-format"]===undefined) props.mod.parameters["user-certificate-format"]="PEM";
    if (props.mod.parameters["ca-chain"]===undefined) props.mod.parameters["ca-chain"]=[];

    this.state = {
      mod: props.mod,
      role: props.role,
      check: props.check,
      certFile: false,
      fileName: false,
      requestCertFile: {},
      requestCertFileName: {},
      useCAChain: props.mod.parameters["ca-chain"].length,
      hasError: false,
      errorList: {}
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.setCertSource = this.setCertSource.bind(this);
    this.setBooleanValue = this.setBooleanValue.bind(this);
    this.setTextValue = this.setTextValue.bind(this);
    this.checkParameters = this.checkParameters.bind(this);
    this.setUseCaChain = this.setUseCaChain.bind(this);
    this.setValue = this.setValue.bind(this);
    this.selectCertFile = this.selectCertFile.bind(this);
    this.addCertificateFile = this.addCertificateFile.bind(this);
    this.deleteCertificateFile = this.deleteCertificateFile.bind(this);
    this.setRequestCertificate = this.setRequestCertificate.bind(this);
    this.addRequestCertificateFile = this.addRequestCertificateFile.bind(this);
    this.selectRequestCertificateFile = this.selectRequestCertificateFile.bind(this);
    this.setRequestCertificateExpiration = this.setRequestCertificateExpiration.bind(this);
    this.setDnFormatValue = this.setDnFormatValue.bind(this);
    this.setRequestCertificateAllowMultiple = this.setRequestCertificateAllowMultiple.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    
    if (nextProps.mod===undefined) nextProps.mod = {};
    if (nextProps.mod.parameters===undefined) nextProps.mod.parameters = {};
    if (nextProps.mod.parameters["cert-source"]===undefined) nextProps.mod.parameters["cert-source"]="TLS";
    if (nextProps.mod.parameters["header-name"]===undefined) nextProps.mod.parameters["header-name"]="SSL_CLIENT_CERT";
    if (nextProps.mod.parameters["use-scheme-storage"]===undefined) nextProps.mod.parameters["use-scheme-storage"]=false;
    if (nextProps.mod.parameters["user-certificate-property"]===undefined) nextProps.mod.parameters["user-certificate-property"]="";
    if (nextProps.mod.parameters["user-certificate-format"]===undefined) nextProps.mod.parameters["user-certificate-format"]="PEM";
    if (nextProps.mod.parameters["ca-chain"]===undefined) nextProps.mod.parameters["ca-chain"]=[];

    this.setState({
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check,
      certFile: false,
      fileName: false,
      useCAChain: nextProps.mod.parameters["ca-chain"].length
    }, () => {
      if (this.state.check) {
        this.checkParameters();
      }
    });
  }
  
  setCertSource(e, source) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["cert-source"] = source;
    this.setState({mod: mod});
  }
  
  setUseCaChain(value) {
    var mod = this.state.mod;
    if (!value) {
      mod.parameters["ca-chain"] = [];
    }
    this.setState({useCAChain: value, mod: mod});
  }
  
  selectCertFile(e) {
    var profile = this.state.profile;
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      this.setState({certFile: ev2.target.result, fileName: file.name});
    };
    fr.readAsText(file);
  }
  
  addCertificateFile() {
    if (this.state.certFile) {
      var mod = this.state.mod;
      mod.parameters["ca-chain"].push({"file-name": this.state.fileName, "cert-file": this.state.certFile});
      this.setState({mod: mod, certFile: false, fileName: false});
    }
  }
  
  selectRequestCertificateFile(e, property) {
    var profile = this.state.profile;
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      var requestCertFileName = this.state.requestCertFileName;
      var requestCertFile = this.state.requestCertFile;
      requestCertFile[property] = ev2.target.result;
      requestCertFileName[property] = file.name;
      this.setState({requestCertFile: requestCertFile, requestCertFileName: requestCertFileName});
    };
    fr.readAsText(file);
  }
  
  addRequestCertificateFile(property) {
    if (this.state.requestCertFile[property]) {
      var mod = this.state.mod;
      var requestCertFileName = this.state.requestCertFileName;
      var requestCertFile = this.state.requestCertFile;
      mod.parameters["request-certificate"][property] = {
        "file-name": requestCertFileName[property],
        "cert-file": requestCertFile[property]
      }
      delete(requestCertFileName[property]);
      delete(requestCertFile[property]);
      this.setState({mod: mod, requestCertFileName: requestCertFileName, requestCertFile: requestCertFile});
    }
  }
  
  deleteCertificateFile(e, index) {
    var mod = this.state.mod;
    mod.parameters["ca-chain"].splice(index, 1);
    this.setState({mod: mod});
  }
  
  setBooleanValue(e, param, value) {
    var mod = this.state.mod;
    mod.parameters[param] = value;
    this.setState({mod: mod});
  }
  
  setTextValue(e, param) {
    var mod = this.state.mod;
    mod.parameters[param] = e.target.value;
    this.setState({mod: mod});
  }
  
  setValue(e, param, value) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters[param] = value;
    this.setState({mod: mod});
  }
  
  setRequestCertificate(e, value) {
    e.preventDefault();
    var mod = this.state.mod;
    if (value) {
      mod.parameters["request-certificate"] = {
        "issuer-cert": {"file-name": "", "cert-file": ""},
        "issuer-key": {"file-name": "", "cert-file": ""},
        "expiration": 60*60*24*365, // 1 year
        "dn-format": "cn={username},dc=glewlwyd,dc=tld",
        "allow-multiple": false
      };
    } else {
      delete(mod.parameters["request-certificate"]);
    }
    this.setState({mod: mod});
  }
  
  setRequestCertificateExpiration(e) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["request-certificate"]["expiration"] = parseInt(e.target.value);
    this.setState({mod: mod});
  }
  
  setDnFormatValue(e) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["request-certificate"]["dn-format"] = e.target.value;
    this.setState({mod: mod});
  }
  
  setRequestCertificateAllowMultiple(e, value) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["request-certificate"]["allow-multiple"] = value;
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["use-scheme-storage"]) {
      if (this.state.mod.parameters["user-certificate-property"] === "") {
        hasError = true;
        errorList["user-certificate-property"] = i18next.t("admin.mod-certificate-user-certificate-property-error")
      }
    }
    if (!this.state.mod.parameters["header-name"]) {
      if (this.state.mod.parameters["header-name"] === "") {
        hasError = true;
        errorList["header-name"] = i18next.t("admin.mod-certificate-header-name-error")
      }
    }
    if (this.state.mod.parameters["request-certificate"]) {
      if (this.state.mod.parameters["request-certificate"]["dn-format"] === "") {
        hasError = true;
        errorList["request-certificate-dn"] = i18next.t("admin.mod-certificate-request-certificate-dn-error")
      }
      if (!this.state.mod.parameters["request-certificate"]["expiration"]) {
        hasError = true;
        errorList["request-certificate-expiration"] = i18next.t("admin.mod-certificate-request-certificate-expiration-error")
      }
      if (this.state.mod.parameters["request-certificate"]["issuer-key"]["cert-file"] === "" || this.state.mod.parameters["request-certificate"]["issuer-key"]["file-name"] === "") {
        hasError = true;
        errorList["request-certificate-issuer-key"] = i18next.t("admin.mod-certificate-request-certificate-issuer-key-error")
      }
      if (this.state.mod.parameters["request-certificate"]["issuer-cert"]["cert-file"] === "" || this.state.mod.parameters["request-certificate"]["issuer-cert"]["file-name"] === "") {
        hasError = true;
        errorList["request-certificate-issuer-cert"] = i18next.t("admin.mod-certificate-request-certificate-issuer-cert-error")
      }
    }
    if (!hasError) {
      this.setState({errorList: {}}, () => {
        messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
      });
    } else {
      this.setState({errorList: errorList}, () => {
        messageDispatcher.sendMessage('ModEdit', {type: "modInvalid"});
      });
    }
  }
  
  render() {
    var CAChainList = [], uploadButton, requestCertificate;
    if (this.state.useCAChain) {
      this.state.mod.parameters["ca-chain"].forEach((cert, index) => {
        CAChainList.push(
          <div className="alert alert-primary" key={index}>
            {cert["file-name"].substring(0, 40)}
            <button type="button" className="close" aria-label={i18next.t("admin.mod-certificate-user-certificate-ca-chain-delete")} onClick={(e) => this.deleteCertificateFile(e, index)}>
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
        );
      });
      uploadButton = 
      <div className="input-group mb-3">
        <div className="input-group-prepend">
          <button className="btn btn-outline-secondary" type="button" id="addCertificateFromFile" title={i18next.t("admin.mod-certificate-user-certificate-ca-chain-add-from-file")} onClick={this.addCertificateFile}>
            {i18next.t("upload")}
          </button>
        </div>
        <div className="custom-file">
          <input disabled={!this.state.useCAChain} type="file" className="custom-file-input" id="addCertificateFromFileInput" aria-describedby="addCertificateFromFile" onChange={(e) => this.selectCertFile(e)} />
          <label className="custom-file-label" htmlFor="addCertificateFromFile">
            {this.state.fileName||i18next.t("browse")}
          </label>
        </div>
      </div>
    }
    if (this.state.mod.parameters["request-certificate"]) {
      requestCertificate = 
      <div>
        <div className="form-group">
          <div className="alert alert-primary">
            {i18next.t("admin.mod-certificate-request-certificate-select-issuer-cert", {file: this.state.mod.parameters["request-certificate"]["issuer-cert"]["file-name"].substring(0, 40)})}
          </div>
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <button className="btn btn-outline-secondary" type="button" id="addRequestCertificateCertFromFile" title={i18next.t("admin.mod-certificate-request-certificate-add-from-file")} onClick={() => this.addRequestCertificateFile("issuer-cert")}>
                {i18next.t("upload")}
              </button>
            </div>
            <div className="custom-file">
              <input type="file" className="custom-file-input" id="addRequestCertificateCertFromFileInput" aria-describedby="addRequestCertificateCertFromFile" onChange={(e) => this.selectRequestCertificateFile(e, "issuer-cert")} />
              <label className="custom-file-label" htmlFor="addRequestCertificateCertFromFile">
                {this.state.requestCertFileName["issuer-cert"]||i18next.t("browse")}
              </label>
            </div>
          </div>
          {this.state.errorList["request-certificate-issuer-cert"]?<span className="error-input">{i18next.t(this.state.errorList["request-certificate-issuer-cert"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="alert alert-primary">
            {i18next.t("admin.mod-certificate-request-certificate-select-issuer-key", {file: this.state.mod.parameters["request-certificate"]["issuer-key"]["file-name"].substring(0, 40)})}
          </div>
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <button className="btn btn-outline-secondary" type="button" id="addRequestCertificateKeyFromFile" title={i18next.t("admin.mod-certificate-request-certificate-add-from-file")} onClick={() => this.addRequestCertificateFile("issuer-key")}>
                {i18next.t("upload")}
              </button>
            </div>
            <div className="custom-file">
              <input type="file" className="custom-file-input" id="addRequestCertificateKeyFromFileInput" aria-describedby="addRequestCertificateKeyFromFile" onChange={(e) => this.selectRequestCertificateFile(e, "issuer-key")} />
              <label className="custom-file-label" htmlFor="addRequestCertificateKeyFromFile">
                {this.state.requestCertFileName["issuer-key"]||i18next.t("browse")}
              </label>
            </div>
          </div>
          {this.state.errorList["request-certificate-issuer-key"]?<span className="error-input">{i18next.t(this.state.errorList["request-certificate-issuer-key"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-certificate-request-certificate-expiration">{i18next.t("admin.mod-certificate-request-certificate-expiration")}</label>
            </div>
            <input type="number" min="1" step="1" className={this.state.errorList["request-certificate-expiration"]?"form-control is-invalid":"form-control"} id="mod-certificate-header-name" placeholder={i18next.t("admin.mod-certificate-request-certificate-expiration-ph")} value={this.state.mod.parameters["request-certificate"]["expiration"]} onChange={(e) => this.setRequestCertificateExpiration(e)}/>
          </div>
          {this.state.errorList["request-certificate-expiration"]?<span className="error-input">{i18next.t(this.state.errorList["request-certificate-expiration"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-certificate-request-certificate-dn">{i18next.t("admin.mod-certificate-request-certificate-dn")}</label>
            </div>
            <input type="text" className={this.state.errorList["request-certificate-dn"]?"form-control is-invalid":"form-control"} id="mod-certificate-request-certificate-dn" placeholder={i18next.t("admin.mod-certificate-request-certificate-dn-ph")} value={this.state.mod.parameters["request-certificate"]["dn-format"]} onChange={(e) => this.setDnFormatValue(e)}/>
          </div>
          {this.state.errorList["request-certificate-dn"]?<span className="error-input">{i18next.t(this.state.errorList["request-certificate-dn"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-certificate-request-certificate-allow-multiple">{i18next.t("admin.mod-certificate-request-certificate-allow-multiple")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-certificate-request-certificate-allow-multiple" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.mod-certificate-value-"+(this.state.mod.parameters["request-certificate"]["allow-multiple"]?"yes":"no"))}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-certificate-request-certificate-allow-multiple">
                <a className={"dropdown-item"+(this.state.mod.parameters["request-certificate"]["allow-multiple"]?" active":"")} href="#" onClick={(e) => this.setRequestCertificateAllowMultiple(e, true)}>{i18next.t("admin.mod-certificate-value-yes")}</a>
                <a className={"dropdown-item"+(!this.state.mod.parameters["request-certificate"]["allow-multiple"]?" active":"")} href="#" onClick={(e) => this.setRequestCertificateAllowMultiple(e, false)}>{i18next.t("admin.mod-certificate-value-no")}</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    }
    return (
      <div>
        <hr/>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-certificate-cert-source">{i18next.t("admin.mod-certificate-cert-source")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-certificate-cert-source" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.mod-certificate-cert-source-"+this.state.mod.parameters["cert-source"])}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-certificate-cert-source">
                <a className={"dropdown-item"+(this.state.mod.parameters["cert-source"]==="TLS"?" active":"")} href="#" onClick={(e) => this.setCertSource(e, "TLS")}>{i18next.t("admin.mod-certificate-cert-source-TLS")}</a>
                <a className={"dropdown-item"+(this.state.mod.parameters["cert-source"]==="header"?" active":"")} href="#" onClick={(e) => this.setCertSource(e, "header")}>{i18next.t("admin.mod-certificate-cert-source-header")}</a>
                <a className={"dropdown-item"+(this.state.mod.parameters["cert-source"]==="both"?" active":"")} href="#" onClick={(e) => this.setCertSource(e, "both")}>{i18next.t("admin.mod-certificate-cert-source-both")}</a>
              </div>
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-certificate-header-name">{i18next.t("admin.mod-certificate-header-name")}</label>
            </div>
            <input type="text" disabled={this.state.mod.parameters["cert-source"]==="TLS"} className={this.state.errorList["header-name"]?"form-control is-invalid":"form-control"} id="mod-certificate-header-name" placeholder={i18next.t("admin.mod-certificate-header-name-ph")} value={this.state.mod.parameters["header-name"]} onChange={(e) => this.setTextValue(e, "header-name")}/>
          </div>
          {this.state.errorList["header-name"]?<span className="error-input">{i18next.t(this.state.errorList["header-name"])}</span>:""}
        </div>
        <hr/>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-certificate-request-certificate-enabled">{i18next.t("admin.mod-certificate-request-certificate-enabled")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-certificate-request-certificate-enabled" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.mod-certificate-value-"+(this.state.mod.parameters["request-certificate"]!==undefined?"yes":"no"))}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-certificate-request-certificate-enabled">
                <a className={"dropdown-item"+(this.state.mod.parameters["request-certificate"]?" active":"")} href="#" onClick={(e) => this.setRequestCertificate(e, true)}>{i18next.t("admin.mod-certificate-value-yes")}</a>
                <a className={"dropdown-item"+(!this.state.mod.parameters["request-certificate"]?" active":"")} href="#" onClick={(e) => this.setRequestCertificate(e, false)}>{i18next.t("admin.mod-certificate-value-no")}</a>
              </div>
            </div>
          </div>
        </div>
        {requestCertificate}
        <hr/>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-certificate-use-scheme-storage">{i18next.t("admin.mod-certificate-use-scheme-storage")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-certificate-use-scheme-storage" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.mod-certificate-value-"+(this.state.mod.parameters["use-scheme-storage"]?"yes":"no"))}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-certificate-use-scheme-storage">
                <a className={"dropdown-item"+(this.state.mod.parameters["use-scheme-storage"]?" active":"")} href="#" onClick={(e) => this.setBooleanValue(e, "use-scheme-storage", true)}>{i18next.t("admin.mod-certificate-value-yes")}</a>
                <a className={"dropdown-item"+(!this.state.mod.parameters["use-scheme-storage"]?" active":"")} href="#" onClick={(e) => this.setBooleanValue(e, "use-scheme-storage", false)}>{i18next.t("admin.mod-certificate-value-no")}</a>
              </div>
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-certificate-user-certificate-property">{i18next.t("admin.mod-certificate-user-certificate-property")}</label>
            </div>
            <input type="text" disabled={this.state.mod.parameters["use-scheme-storage"]} className={this.state.errorList["user-certificate-property"]?"form-control is-invalid":"form-control"} id="mod-certificate-user-certificate-property" placeholder={i18next.t("admin.mod-certificate-user-certificate-property-ph")} maxLength="256" value={this.state.mod.parameters["user-certificate-property"]} onChange={(e) => this.setTextValue(e, "user-certificate-property")}/>
          </div>
          {this.state.errorList["user-certificate-property"]?<span className="error-input">{i18next.t(this.state.errorList["user-certificate-property"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-certificate-user-certificate-format">{i18next.t("admin.mod-certificate-user-certificate-format")}</label>
            </div>
            <div className="dropdown">
              <button disabled={this.state.mod.parameters["use-scheme-storage"]} className="btn btn-secondary dropdown-toggle" type="button" id="mod-certificate-user-certificate-format" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.mod-certificate-user-certificate-format-"+(this.state.mod.parameters["user-certificate-format"]))}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-certificate-user-certificate-format">
                <a className={"dropdown-item"+(this.state.mod.parameters["user-certificate-format"]?" active":"")} href="#" onClick={(e) => this.setValue(e, "user-certificate-format", "PEM")}>{i18next.t("admin.mod-certificate-user-certificate-format-PEM")}</a>
                <a className={"dropdown-item"+(!this.state.mod.parameters["user-certificate-format"]?" active":"")} href="#" onClick={(e) => this.setValue(e, "user-certificate-format", "DER")}>{i18next.t("admin.mod-certificate-user-certificate-format-DER")}</a>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionParams">
          <div className="card">
            <div className="card-header" id="CAChainCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseCAChain" aria-expanded="true" aria-controls="collapseCAChain">
                  {i18next.t("admin.mod-certificate-user-certificate-ca-chain")}
                </button>
              </h2>
            </div>
            <div id="collapseCAChain" className="collapse" aria-labelledby="CAChainCard" data-parent="#accordionParams">
              <div className="card-body">
                <p>{i18next.t("admin.mod-certificate-user-certificate-ca-chain-message")}</p>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-certificate-use-ca-chain">{i18next.t("admin.mod-certificate-use-ca-chain")}</label>
                    </div>
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-certificate-use-ca-chain" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        {i18next.t("admin.mod-certificate-value-"+(this.state.useCAChain?"yes":"no"))}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="mod-certificate-use-ca-chain">
                        <a className={"dropdown-item"+(this.state.useCAChain?" active":"")} href="#" onClick={(e) => this.setUseCaChain(true)}>{i18next.t("admin.mod-certificate-value-yes")}</a>
                        <a className={"dropdown-item"+(!this.state.useCAChain?" active":"")} href="#" onClick={(e) => this.setUseCaChain(false)}>{i18next.t("admin.mod-certificate-value-no")}</a>
                      </div>
                    </div>
                  </div>
                </div>
                {CAChainList}
                {uploadButton}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default CertificateParams;
