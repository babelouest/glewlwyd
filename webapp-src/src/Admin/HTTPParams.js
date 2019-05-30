import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class HTTPParams extends Component {
  constructor(props) {
    super(props);

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
    this.toggleCheckServerCertificate = this.toggleCheckServerCertificate.bind(this);
    this.checkParameters = this.checkParameters.bind(this);
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
  
  changeParam(e, param) {
    var mod = this.state.mod;
    mod.parameters[param] = e.target.value;
    this.setState({mod: mod});
  }
  
  toggleCheckServerCertificate() {
    var mod = this.state.mod;
    mod.parameters["check-server-certificate"] = !mod.parameters["check-server-certificate"];
    this.setState({mod: mod});
  }
  
  addScope(e, scope) {
    var mod = this.state.mod;
    if (!mod.parameters["default-scope"]) {
      mod.parameters["default-scope"] = [scope];
    } else {
      mod.parameters["default-scope"].push(scope);
    }
    this.setState({mod: mod});
  }
  
  deleteDefaultScope(e, index) {
    var mod = this.state.mod;
    mod.parameters["default-scope"].splice(index, 1);
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["url"]) {
      hasError = true;
      errorList["url"] = i18next.t("admin.mod-http-url-error")
    }
    if (!this.state.mod.parameters["default-scope"]) {
      hasError = true;
      errorList["default-scope"] = i18next.t("admin.mod-http-default-scope-error")
    }
    if (!hasError) {
      this.setState({errorList: {}}, () => {
        if (this.state.role === "user") {
          messageDispatcher.sendMessage('ModEditUser', {type: "modValid"});
        } else if (this.state.role === "client") {
          messageDispatcher.sendMessage('ModEditClient', {type: "modValid"});
        }
      });
    } else {
      this.setState({errorList: errorList});
    }
  }
  
  render() {
    var scopeList = [], defaultScopeList = [];
    this.state.config.pattern.user.forEach((pattern) => {
      if (pattern.name === "scope") {
        pattern.listElements.forEach((scope, index) => {
          scopeList.push(<a key={index} className="dropdown-item" href="#" onClick={(e) => this.addScope(e, scope)}>{scope}</a>);
        });
      }
    });
    if (this.state.mod.parameters["default-scope"]) {
      this.state.mod.parameters["default-scope"].forEach((scope, index) => {
        defaultScopeList.push(<a href="#" onClick={(e) => this.deleteDefaultScope(e, index)} key={index}><span className="badge badge-primary">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
      });
    }
    var scopeJsx = 
      <div className="dropdown">
        <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-http-default-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          {i18next.t("admin.mod-http-default-scope")}
        </button>
        <div className="dropdown-menu" aria-labelledby="mod-http-default-scope">
          {scopeList}
        </div>
        <div>
          {defaultScopeList}
        </div>
      </div>;
    return (
      <div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-http-url">{i18next.t("admin.mod-http-url")}</label>
            </div>
            <input type="text" className={this.state.errorList["url"]?"form-control is-invalid":"form-control"} id="mod-http-url" onChange={(e) => this.changeParam(e, "url")} value={this.state.mod.parameters["url"]} placeholder={i18next.t("admin.mod-http-url-ph")} />
          </div>
          {this.state.errorList["url"]?<span className="error-input">{i18next.t(this.state.errorList["url"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-check-server-certificate">{i18next.t("admin.mod-check-server-certificate")}</label>
            </div>
            <div className="input-group-text">
              <input type="checkbox" className="form-control" id="mod-check-server-certificate" onChange={(e) => this.toggleCheckServerCertificate()} checked={this.state.mod.parameters["check-server-certificate"]||false} />
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-default-scope">{i18next.t("admin.mod-http-default-scope")}</label>
            </div>
            {scopeJsx}
          </div>
          {this.state.errorList["default-scope"]?<span className="error-input">{i18next.t(this.state.errorList["default-scope"])}</span>:""}
        </div>
      </div>
    );
  }
}

export default HTTPParams;
