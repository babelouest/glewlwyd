import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class GlwdOauth2Params extends Component {
  constructor(props) {
    super(props);
    
    props.mod.parameters?"":(props.mod.parameters = {});
    props.mod.parameters["jwt-type"]?"":(props.mod.parameters["jwt-type"] = "rsa");
    props.mod.parameters["jwt-key-size"]?"":(props.mod.parameters["jwt-key-size"] = "512");
    props.mod.parameters["key"]?"":(props.mod.parameters["key"] = "");
    props.mod.parameters["cert"]?"":(props.mod.parameters["cert"] = "");
    props.mod.parameters["cert"]?"":(props.mod.parameters["cert"] = "");
    props.mod.parameters["access-token-duration"]?"":(props.mod.parameters["access-token-duration"] = 3600);
    props.mod.parameters["refresh-token-duration"]?"":(props.mod.parameters["refresh-token-duration"] = 1209600);
    props.mod.parameters["code-duration"]?"":(props.mod.parameters["code-duration"] = 600);
    props.mod.parameters["refresh-token-rolling"]!==undefined?"":(props.mod.parameters["refresh-token-rolling"] = true);
    props.mod.parameters["auth-type-code-enabled"]!==undefined?"":(props.mod.parameters["auth-type-code-enabled"] = true);
    props.mod.parameters["auth-type-implicit-enabled"]!==undefined?"":(props.mod.parameters["auth-type-implicit-enabled"] = true);
    props.mod.parameters["auth-type-password-enabled"]!==undefined?"":(props.mod.parameters["auth-type-password-enabled"] = true);
    props.mod.parameters["auth-type-client-enabled"]!==undefined?"":(props.mod.parameters["auth-type-client-enabled"] = true);
    props.mod.parameters["auth-type-refresh-enabled"]!==undefined?"":(props.mod.parameters["auth-type-refresh-enabled"] = true);
    props.mod.parameters["scope"]?"":(props.mod.parameters["scope"] = []);

    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check,
      errorList: {},
      newScopeOverride: false
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.checkParameters = this.checkParameters.bind(this);
    this.changeParam = this.changeParam.bind(this);
    this.changeNumberParam = this.changeNumberParam.bind(this);
    this.toggleParam = this.toggleParam.bind(this);
    this.changeJwtType = this.changeJwtType.bind(this);
    this.setNewScopeOverride = this.setNewScopeOverride.bind(this);
    this.addScopeOverride = this.addScopeOverride.bind(this);
    this.changeScopeOverrideRefreshDuration = this.changeScopeOverrideRefreshDuration.bind(this);
    this.toggleScopeOverrideRolling = this.toggleScopeOverrideRolling.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    
    nextProps.mod.parameters?"":(nextProps.mod.parameters = {});
    nextProps.mod.parameters["jwt-type"]?"":(nextProps.mod.parameters["jwt-type"] = "rsa");
    nextProps.mod.parameters["jwt-key-size"]?"":(nextProps.mod.parameters["jwt-key-size"] = "512");
    nextProps.mod.parameters["key"]?"":(nextProps.mod.parameters["key"] = "");
    nextProps.mod.parameters["cert"]?"":(nextProps.mod.parameters["cert"] = "");
    nextProps.mod.parameters["cert"]?"":(nextProps.mod.parameters["cert"] = "");
    nextProps.mod.parameters["access-token-duration"]?"":(nextProps.mod.parameters["access-token-duration"] = 3600);
    nextProps.mod.parameters["refresh-token-duration"]?"":(nextProps.mod.parameters["refresh-token-duration"] = 1209600);
    nextProps.mod.parameters["code-duration"]?"":(nextProps.mod.parameters["code-duration"] = 600);
    nextProps.mod.parameters["refresh-token-rolling"]!==undefined?"":(nextProps.mod.parameters["refresh-token-rolling"] = true);
    nextProps.mod.parameters["auth-type-code-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-code-enabled"] = true);
    nextProps.mod.parameters["auth-type-implicit-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-implicit-enabled"] = true);
    nextProps.mod.parameters["auth-type-password-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-password-enabled"] = true);
    nextProps.mod.parameters["auth-type-client-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-client-enabled"] = true);
    nextProps.mod.parameters["auth-type-refresh-enabled"]!==undefined?"":(nextProps.mod.parameters["auth-type-refresh-enabled"] = true);
    nextProps.mod.parameters["scope"]?"":(nextProps.mod.parameters["scope"] = []);

    this.setState({
      config: nextProps.config,
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check
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
  
  changeNumberParam(e, param) {
    var mod = this.state.mod;
    mod.parameters[param] = parseInt(e.target.value);
    this.setState({mod: mod});
  }
  
  toggleParam(e, param) {
    var mod = this.state.mod;
    mod.parameters[param] = !mod.parameters[param];
    this.setState({mod: mod});
  }
  
  changeJwtType(e, type) {
    var mod = this.state.mod;
    mod.parameters["jwt-type"] = type;
    this.setState({mod: mod});
  }
  
  changeJwtKeySize(e, size) {
    var mod = this.state.mod;
    mod.parameters["jwt-key-size"] = type;
    this.setState({mod: mod});
  }
  
  uploadFile(e, name) {
    var mod = this.state.mod;
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      mod.parameters[name] = ev2.target.result;
      this.setState({mod: mod});
    };
    fr.readAsText(file);
  }
  
  setNewScopeOverride(e, scope) {
    this.setState({newScopeOverride: scope});
  }
  
  addScopeOverride() {
    if (this.state.newScopeOverride) {
      var mod = this.state.mod;
      mod.parameters["scope"].push({
        name: this.state.newScopeOverride, 
        "refresh-token-rolling": this.state.mod.parameters["refresh-token-rolling"], 
        "refresh-token-duration": 0
      });
      this.setState({mod: mod, newScopeOverride: false});
    }
  }
  
  changeScopeOverrideRefreshDuration(e, scope) {
    var mod = this.state.mod;
    mod.parameters["scope"].forEach((curScope) => {
      if (curScope.name === scope) {
        curScope["refresh-token-duration"] = e.target.value;
      }
    });
    this.setState({mod: mod});
  }
  
  toggleScopeOverrideRolling(e, scope) {
    var mod = this.state.mod;
    mod.parameters["scope"].forEach((curScope) => {
      if (curScope.name === scope) {
        curScope["refresh-token-rolling"] = !curScope["refresh-token-rolling"];
      }
    });
    this.setState({mod: mod});
  }
  
  deleteScopeOverride(e, scope) {
    var mod = this.state.mod;
    mod.parameters["scope"].forEach((curScope, index) => {
      if (curScope.name === scope) {
        mod.parameters["scope"].splice(index, 1);
      }
    });
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["url"]) {
      hasError = true;
      errorList["url"] = "admin.mod-glwd-url-error"
    }
    if (!this.state.mod.parameters["key"]) {
      hasError = true;
      errorList["key"] = "admin.mod-glwd-key-error"
    }
    if (this.state.mod.parameters["jwt-type"] !== "sha" && !this.state.mod.parameters["cert"]) {
      hasError = true;
      errorList["cert"] = "admin.mod-glwd-cert-error"
    }
    if (!this.state.mod.parameters["access-token-duration"]) {
      hasError = true;
      errorList["access-token-duration"] = "admin.mod-glwd-access-token-duration-error"
    }
    if (!this.state.mod.parameters["refresh-token-duration"]) {
      hasError = true;
      errorList["refresh-token-duration"] = "admin.mod-glwd-refresh-token-duration-error"
    }
    if (!this.state.mod.parameters["code-duration"]) {
      hasError = true;
      errorList["code-duration"] = "admin.mod-glwd-code-duration-error"
    }
    if (!hasError) {
      this.setState({errorList: {}}, () => {
        messageDispatcher.sendMessage('ModPlugin', {type: "modValid"});
      });
    } else {
      this.setState({errorList: errorList});
    }
  }
  
  render() {
    var keyJsx, certJsx, scopeOverrideList = [], scopeList = [];
    if (this.state.mod.parameters["jwt-type"] === "sha") {
      keyJsx =
        <div className="form-group">
          <label htmlFor="mod-glwd-key">{i18next.t("admin.mod-glwd-key")}</label>
          <input type="password" className={this.state.errorList["key"]?"form-control is-invalid":"form-control"} id="mod-glwd-key" onChange={(e) => this.changeParam(e, "key")} value={this.state.mod.parameters["key"]} placeholder={i18next.t("admin.mod-glwd-key-ph")} />
          {this.state.errorList["key"]?<span className="error-input">{i18next.t(this.state.errorList["key"])}</span>:""}
        </div>;
    } else {
      keyJsx =
        <div className="form-group">
          <label htmlFor="mod-glwd-key">{i18next.t("admin.mod-glwd-key")}</label>
          <input type="file" className={this.state.errorList["key"]?"form-control is-invalid":"form-control"} onChange={(e) => this.uploadFile(e, "key")} />
          {this.state.mod.parameters["key"]?<div className="alert alert-primary">{this.state.mod.parameters["key"].substring(0, 40)}</div>:""}
          {this.state.errorList["key"]?<span className="error-input">{i18next.t(this.state.errorList["key"])}</span>:""}
        </div>;
      certJsx =
        <div className="form-group">
          <label htmlFor="mod-glwd-cert">{i18next.t("admin.mod-glwd-cert")}</label>
          <input type="file" className={this.state.errorList["key"]?"form-control is-invalid":"form-control"} onChange={(e) => this.uploadFile(e, "cert")} />
          {this.state.mod.parameters["cert"]?<div className="alert alert-primary">{this.state.mod.parameters["cert"].substring(0, 40)}</div>:""}
          {this.state.errorList["cert"]?<span className="error-input">{i18next.t(this.state.errorList["cert"])}</span>:""}
        </div>;
    }
    this.state.config.pattern.user.forEach((pattern) => {
      if (pattern.name === "scope") {
        pattern.listElements.forEach((scope, index) => {
          var found = 0;
          this.state.mod.parameters["scope"].forEach((curScope) => {
            if (curScope.name === scope) {
              found = 1;
            }
          });
          if (!found) {
            scopeList.push(<a key={index} className="dropdown-item" href="#" onClick={(e) => this.setNewScopeOverride(e, scope)}>{scope}</a>);
          }
        });
      }
    });
    var scopeJsx = 
      <div className="dropdown">
        <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-glwd-scope-override-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          {this.state.newScopeOverride||i18next.t("admin.mod-glwd-scope-override-scope")}
        </button>
        <div className="dropdown-menu" aria-labelledby="mod-glwd-scope-override-scope">
          {scopeList}
        </div>
      </div>;
    this.state.mod.parameters["scope"].forEach((scope, index) => {
      scopeOverrideList.push(
      <div key={index}>
        <hr/>
        <div className="form-group">
          <label htmlFor={"mod-glwd-scope-override-refresh-duration-"+scope.name}>{i18next.t("admin.mod-glwd-scope-override-refresh-duration")}</label>
          <input type="number" min="0" step="1" className="form-control" id={"mod-glwd-scope-override-refresh-duration-"+scope.name} onChange={(e) => this.changeScopeOverrideRefreshDuration(e, scope)} value={scope["refresh-token-duration"]} placeholder={i18next.t("admin.mod-glwd-scope-override-refresh-duration-ph")} />
        </div>
        <div className="form-group">
          <label htmlFor={"mod-glwd-scope-override-refresh-rolling-"+scope.name}>{i18next.t("admin.mod-scope-override-refresh-rolling")}</label>
          <input type="checkbox" className="form-control" id={"mod-scope-override-refresh-rolling-"+scope.name} onChange={(e) => this.toggleScopeOverrideRolling(e, scope.name)} checked={scope["refresh-token-rolling"]} />
        </div>
        <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteScopeOverride(e, scope.name)} title={i18next.t("admin.mod-scope-override-delete")}>
          <i className="fas fa-trash"></i>
        </button>
      </div>
      );
    });
    return (
      <div>
        <div className="form-group">
          <label htmlFor="mod-glwd-url">{i18next.t("admin.mod-glwd-url")}</label>
          <input type="text" className={this.state.errorList["url"]?"form-control is-invalid":"form-control"} id="mod-glwd-url" onChange={(e) => this.changeParam(e, "url")} value={this.state.mod.parameters["url"]} placeholder={i18next.t("admin.mod-glwd-url-ph")} />
          {this.state.errorList["url"]?<span className="error-input">{i18next.t(this.state.errorList["url"])}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-glwd-jwt-type">{i18next.t("admin.mod-glwd-jwt-type")}</label>
          <div className="dropdown">
            <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-glwd-jwt-type" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              {i18next.t("admin.mod-glwd-jwt-type-" + this.state.mod.parameters["jwt-type"])}
            </button>
            <div className="dropdown-menu" aria-labelledby="mod-glwd-jwt-type">
              <a className={"dropdown-item"+(this.state.mod.parameters["jwt-type"]==="rsa"?" active":"")} href="#" onClick={(e) => this.changeJwtType(e, 'rsa')}>{i18next.t("admin.mod-glwd-jwt-type-rsa")}</a>
              <a className={"dropdown-item"+(this.state.mod.parameters["jwt-type"]==="ecdsa"?" active":"")} href="#" onClick={(e) => this.changeJwtType(e, 'ecdsa')}>{i18next.t("admin.mod-glwd-jwt-type-ecdsa")}</a>
              <a className={"dropdown-item"+(this.state.mod.parameters["jwt-type"]==="sha"?" active":"")} href="#" onClick={(e) => this.changeJwtType(e, 'sha')}>{i18next.t("admin.mod-glwd-jwt-type-sha")}</a>
            </div>
          </div>
          {this.state.errorList["jwt-type"]?<span className="error-input">{i18next.t(this.state.errorList["jwt-type"])}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-glwd-jwt-key-size">{i18next.t("admin.mod-glwd-jwt-key-size")}</label>
          <div className="dropdown">
            <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-glwd-jwt-key-size" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              {i18next.t("admin.mod-glwd-jwt-key-size-" + this.state.mod.parameters["jwt-key-size"])}
            </button>
            <div className="dropdown-menu" aria-labelledby="mod-glwd-jwt-key-size">
              <a className={"dropdown-item"+(this.state.mod.parameters["jwt-key-size"]==="256"?" active":"")} href="#" onClick={(e) => this.changeJwtKeySize(e, '256')}>{i18next.t("admin.mod-glwd-jwt-key-size-256")}</a>
              <a className={"dropdown-item"+(this.state.mod.parameters["jwt-key-size"]==="384"?" active":"")} href="#" onClick={(e) => this.changeJwtKeySize(e, '384')}>{i18next.t("admin.mod-glwd-jwt-key-size-384")}</a>
              <a className={"dropdown-item"+(this.state.mod.parameters["jwt-key-size"]==="512"?" active":"")} href="#" onClick={(e) => this.changeJwtKeySize(e, '512')}>{i18next.t("admin.mod-glwd-jwt-key-size-512")}</a>
            </div>
          </div>
          {this.state.errorList["jwt-key-size"]?<span className="error-input">{i18next.t(this.state.errorList["jwt-key-size"])}</span>:""}
        </div>
        {keyJsx}
        {certJsx}
        <div className="form-group">
          <label htmlFor="mod-glwd-access-token-duration">{i18next.t("admin.mod-glwd-access-token-duration")}</label>
          <input type="number" min="0" step="1" className={this.state.errorList["access-token-duration"]?"form-control is-invalid":"form-control"} id="mod-glwd-access-token-duration" onChange={(e) => this.changeNumberParam(e, "access-token-duration")} value={this.state.mod.parameters["access-token-duration"]} placeholder={i18next.t("admin.mod-glwd-access-token-duration-ph")} />
          {this.state.errorList["access-token-duration"]?<span className="error-input">{i18next.t(this.state.errorList["access-token-duration"])}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-glwd-refresh-token-duration">{i18next.t("admin.mod-glwd-refresh-token-duration")}</label>
          <input type="number" min="0" step="1" className={this.state.errorList["refresh-token-duration"]?"form-control is-invalid":"form-control"} id="mod-glwd-refresh-token-duration" onChange={(e) => this.changeNumberParam(e, "refresh-token-duration")} value={this.state.mod.parameters["refresh-token-duration"]} placeholder={i18next.t("admin.mod-glwd-refresh-token-duration-ph")} />
          {this.state.errorList["refresh-token-duration"]?<span className="error-input">{i18next.t(this.state.errorList["refresh-token-duration"])}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-glwd-code-duration">{i18next.t("admin.mod-glwd-code-duration")}</label>
          <input type="number" min="0" step="1" className={this.state.errorList["code-duration"]?"form-control is-invalid":"form-control"} id="mod-glwd-code-duration" onChange={(e) => this.changeNumberParam(e, "code-duration")} value={this.state.mod.parameters["code-duration"]} placeholder={i18next.t("admin.mod-glwd-code-duration-ph")} />
          {this.state.errorList["code-duration"]?<span className="error-input">{i18next.t(this.state.errorList["code-duration"])}</span>:""}
        </div>
        <div className="form-group">
          <label htmlFor="mod-glwd-refresh-token-rolling">{i18next.t("admin.mod-glwd-refresh-token-rolling")}</label>
          <input type="checkbox" className="form-control" id="mod-glwd-refresh-token-rolling" onChange={(e) => this.toggleParam(e, "refresh-token-rolling")} checked={this.state.mod.parameters["refresh-token-rolling"]} />
        </div>
        <hr/>
        <div className="form-group">
          <label htmlFor="mod-glwd-auth-type-code-enabled">{i18next.t("admin.mod-glwd-auth-type-code-enabled")}</label>
          <input type="checkbox" className="form-control" id="mod-glwd-auth-type-code-enabled" onChange={(e) => this.toggleParam(e, "auth-type-code-enabled")} checked={this.state.mod.parameters["auth-type-code-enabled"]} />
        </div>
        <div className="form-group">
          <label htmlFor="mod-glwd-auth-type-implicit-enabled">{i18next.t("admin.mod-glwd-auth-type-implicit-enabled")}</label>
          <input type="checkbox" className="form-control" id="mod-glwd-auth-type-implicit-enabled" onChange={(e) => this.toggleParam(e, "auth-type-implicit-enabled")} checked={this.state.mod.parameters["auth-type-implicit-enabled"]} />
        </div>
        <div className="form-group">
          <label htmlFor="mod-glwd-auth-type-password-enabled">{i18next.t("admin.mod-glwd-auth-type-password-enabled")}</label>
          <input type="checkbox" className="form-control" id="mod-glwd-auth-type-password-enabled" onChange={(e) => this.toggleParam(e, "auth-type-password-enabled")} checked={this.state.mod.parameters["auth-type-password-enabled"]} />
        </div>
        <div className="form-group">
          <label htmlFor="mod-glwd-auth-type-client-enabled">{i18next.t("admin.mod-glwd-auth-type-client-enabled")}</label>
          <input type="checkbox" className="form-control" id="mod-glwd-auth-type-client-enabled" onChange={(e) => this.toggleParam(e, "auth-type-client-enabled")} checked={this.state.mod.parameters["auth-type-client-enabled"]} />
        </div>
        <div className="form-group">
          <label htmlFor="mod-glwd-auth-type-refresh-enabled">{i18next.t("admin.mod-glwd-auth-type-refresh-enabled")}</label>
          <input type="checkbox" className="form-control" id="mod-glwd-auth-type-refresh-enabled" onChange={(e) => this.toggleParam(e, "auth-type-refresh-enabled")} checked={this.state.mod.parameters["auth-type-refresh-enabled"]} />
        </div>
        <div className="accordion" id="accordionScope">
          <div className="card">
            <div className="card-header" id="dataFormatCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseDataFormat" aria-expanded="true" aria-controls="collapseDataFormat">
                  {i18next.t("admin.mod-glwd-scope-override")}
                </button>
              </h2>
            </div>
            <div id="collapseDataFormat" className="collapse" aria-labelledby="dataFormatCard" data-parent="#accordionScope">
              <div className="card-body">
                <p>{i18next.t("admin.mod-glwd-scope-override-message")}</p>
                <div className="btn-group" role="group">
                  <div className="btn-group" role="group">
                    {scopeJsx}
                  </div>
                  <button type="button" className="btn btn-secondary" onClick={this.addScopeOverride} title={i18next.t("admin.mod-glwd-scope-add")}>
                    <i className="fas fa-plus"></i>
                  </button>
                </div>
                {scopeOverrideList}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default GlwdOauth2Params;
