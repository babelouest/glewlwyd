import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class CertificateParams extends Component {
  constructor(props) {
    super(props);
    
    if (props.mod===undefined) props.mod = {};
    if (props.mod.parameters===undefined) props.mod.parameters = {};
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
      useCAChain: props.mod.parameters["ca-chain"].length,
      hasError: false,
      errorList: {}
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.setBooleanValue = this.setBooleanValue.bind(this);
    this.setTextValue = this.setTextValue.bind(this);
    this.checkParameters = this.checkParameters.bind(this);
    this.setUseCaChain = this.setUseCaChain.bind(this);
    this.setValue = this.setValue.bind(this);
    this.selectCertFile = this.selectCertFile.bind(this);
    this.addCertificateFile = this.addCertificateFile.bind(this);
    this.deleteCertificateFile = this.deleteCertificateFile.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    
    if (nextProps.mod===undefined) nextProps.mod = {};
    if (nextProps.mod.parameters===undefined) nextProps.mod.parameters = {};
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
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["use-scheme-storage"]) {
      if (this.state.mod.parameters["user-certificate-property"] === "") {
        hasError = true;
        errorList["user-certificate-property"] = i18next.t("admin.mod-certificate-user-certificate-property-error")
      }
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
    var CAChainList = [], uploadButton;
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
      uploadButton = <div className="input-group mb-3">
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
    return (
      <div>
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
