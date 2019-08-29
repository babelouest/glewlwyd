import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class CertificateParams extends Component {
  constructor(props) {
    super(props);
    
    if (props.mod===undefined) props.mod = {};
    if (props.mod.parameters===undefined) props.mod.parameters = {};
    if (props.mod.parameters["use-scheme-storage"]===undefined) props.mod.parameters["use-scheme-storage"]=false;
    if (props.mod.parameters["user-certificate-property"]===undefined) props.mod.parameters["user-certificate-property"]="";

    this.state = {
      mod: props.mod,
      role: props.role,
      check: props.check,
      hasError: false
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.setBooleanValue = this.setBooleanValue.bind(this);
    this.setTextValue = this.setTextValue.bind(this);
    this.checkParameters = this.checkParameters.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    
    if (nextProps.mod===undefined) nextProps.mod = {};
    if (nextProps.mod.parameters===undefined) nextProps.mod.parameters = {};
    if (nextProps.mod.parameters["use-scheme-storage"]===undefined) nextProps.mod.parameters["use-scheme-storage"]=false;
    if (nextProps.mod.parameters["user-certificate-property"]===undefined) nextProps.mod.parameters["user-certificate-property"]="";

    this.setState({
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
  
  checkParameters() {
    this.setState({hasError: false});
    messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
  }
  
  render() {
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
            <input type="text" disabled={this.state.mod.parameters["use-scheme-storage"]} className="form-control" id="mod-certificate-user-certificate-property" placeholder={i18next.t("admin.mod-certificate-user-certificate-property-ph")} maxLength="256" value={this.state.mod.parameters["user-certificate-property"]} onChange={(e) => this.setTextValue(e, "user-certificate-property")}/>
          </div>
        </div>
      </div>
    );
  }
}

export default CertificateParams;
