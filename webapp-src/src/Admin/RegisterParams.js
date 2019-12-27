import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';

class RegisterParams extends Component {
  constructor(props) {
    super(props);

    if (!props.mod) {
      props.mod = {parameters: {}};
    }
    
    if (!props.mod.parameters["verification-code-length"]) {
      props.mod.parameters["verification-code-length"] = 8;
    }

    if (!props.mod.parameters["verification-code-duration"]) {
      props.mod.parameters["verification-code-duration"] = 600;
    }

    if (!props.mod.parameters["port"]) {
      props.mod.parameters["port"] = 0;
    }

    if (props.mod.parameters["verify-email"] === undefined) {
      props.mod.parameters["verify-email"] = false;
    }

    if (props.mod.parameters["email-is-username"] === undefined) {
      props.mod.parameters["email-is-username"] = false;
    }

    if (props.mod.parameters["scope"] === undefined) {
      props.mod.parameters["scope"] = [props.config.profile_scope];
    }

    if (!props.mod.parameters["set-password"]) {
      props.mod.parameters["set-password"] = "always";
    }

    if (props.mod.parameters["schemes"] === undefined) {
      props.mod.parameters["schemes"] = [];
    }

    if (!props.mod.parameters["session-key"]) {
      props.mod.parameters["session-key"] = "G_REGISTER_SESSION";
    }

    if (!props.mod.parameters["session-duration"]) {
      props.mod.parameters["session-duration"] = 3600;
    }
    
    if (!props.mod.parameters["subject"]) {
      props.mod.parameters["subject"] = "Confirm registration";
    }

    if (!props.mod.parameters["content-type"]) {
      props.mod.parameters["content-type"] = "text/plain; charset=utf-8";
    }

    if (!props.mod.parameters["body-pattern"]) {
      props.mod.parameters["body-pattern"] = "The code is {CODE}\n\n"+window.location.href.split('?')[0].split('#')[0]+"/profile.html?registration=<your_registration_plugin_name>&token={TOKEN}";
    }

    this.state = {
      config: props.config,
      modSchemes: props.modSchemes,
      mod: props.mod,
      role: props.role,
      check: props.check,
      hasError: false,
      errorList: {}
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.checkParameters = this.checkParameters.bind(this);
    this.addScope = this.addScope.bind(this);
    this.deleteScope = this.deleteScope.bind(this);
    this.addScheme = this.addScheme.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    if (!nextProps.mod) {
      nextProps.mod = {parameters: {}};
    }
    
    if (!nextProps.mod.parameters["verification-code-length"]) {
      nextProps.mod.parameters["verification-code-length"] = 8;
    }

    if (!nextProps.mod.parameters["verification-code-duration"]) {
      nextProps.mod.parameters["verification-code-duration"] = 600;
    }

    if (!nextProps.mod.parameters["port"]) {
      nextProps.mod.parameters["port"] = 0;
    }

    if (nextProps.mod.parameters["verify-email"] === undefined) {
      nextProps.mod.parameters["verify-email"] = false;
    }

    if (nextProps.mod.parameters["email-is-username"] === undefined) {
      nextProps.mod.parameters["email-is-username"] = false;
    }

    if (nextProps.mod.parameters["scope"] === undefined) {
      nextProps.mod.parameters["scope"] = [nextProps.config.profile_scope];
    }

    if (!nextProps.mod.parameters["set-password"]) {
      nextProps.mod.parameters["set-password"] = "always";
    }

    if (nextProps.mod.parameters["schemes"] === undefined) {
      nextProps.mod.parameters["schemes"] = [];
    }

    if (!nextProps.mod.parameters["session-key"]) {
      nextProps.mod.parameters["session-key"] = "G_REGISTER_SESSION";
    }

    if (!nextProps.mod.parameters["session-duration"]) {
      nextProps.mod.parameters["session-duration"] = 3600;
    }

    if (!nextProps.mod.parameters["content-type"]) {
      nextProps.mod.parameters["content-type"] = "text/plain; charset=utf-8";
    }

    if (!nextProps.mod.parameters["subject"]) {
      nextProps.mod.parameters["subject"] = "Confirm registration";
    }

    if (!nextProps.mod.parameters["body-pattern"]) {
      nextProps.mod.parameters["body-pattern"] = "The code is {CODE}\n\n"+window.location.href.split('?')[0].split('#')[0]+"/profile.html?registration=<your_registration_plugin_name>&token={TOKEN}";
    }

    this.setState({
      config: nextProps.config,
      modSchemes: nextProps.modSchemes,
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
  
  toggleParam(e, param) {
    var mod = this.state.mod;
    mod.parameters[param] = !mod.parameters[param];
    this.setState({mod: mod});
  }

  addScope(e, scope) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["scope"].push(scope);
    this.setState({mod: mod});
  }

  deleteScope(e, index) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["scope"].splice(index, 1);
    this.setState({mod: mod});
  }
  
  setPassword(e, value) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["set-password"] = value;
    this.setState({mod: mod});
  }
  
  addScheme() {
    var mod = this.state.mod;
    mod.parameters["schemes"].push({
      "module": "",
      "name": "",
      "register": "yes"
    });
    this.setState({mod: mod});
  }
  
  deleteScheme(index) {
    var mod = this.state.mod;
    mod.parameters["schemes"].splice(index, 1);
    this.setState({mod: mod});
  }
  
  setSchemeName(e, index, name) {
    e.preventDefault();
    var mod = this.state.mod;
    this.state.modSchemes.forEach(scheme => {
      if (scheme.name === name) {
        mod.parameters["schemes"][index]["module"] = scheme.module;
        mod.parameters["schemes"][index]["name"] = scheme.name;
        mod.parameters["schemes"][index]["display_name"] = scheme.display_name;
      }
    });
    this.setState({mod: mod});
  }
  
  setSchemeRegister(e, index, register) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["schemes"][index]["register"] = register;
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false, hasMandatory = false;
    if (!this.state.mod.parameters["session-key"]) {
      hasError = true;
      errorList["session-key"] = i18next.t("admin.mod-register-session-key-error");
    }
    if (!this.state.mod.parameters["session-duration"]) {
      hasError = true;
      errorList["session-duration"] = i18next.t("admin.mod-register-session-duration-error");
    }
    if (!this.state.mod.parameters.scope.length) {
      hasError = true;
      errorList["scope"] = i18next.t("admin.mod-register-scope-error");
    }
    this.state.mod.parameters["schemes"].forEach((scheme) => {
      if (scheme.register === "always") {
        hasMandatory = true;
      }
    });
    if (this.state.mod.parameters["verify-email"]) {
      if (!this.state.mod.parameters["verification-code-length"]) {
        hasError = true;
        errorList["verification-code-length"] = i18next.t("admin.mod-register-verification-code-length-error")
      }
      if (!this.state.mod.parameters["verification-code-duration"]) {
        hasError = true;
        errorList["verification-code-duration"] = i18next.t("admin.mod-register-verification-code-duration-error")
      }
      if (!this.state.mod.parameters["host"]) {
        hasError = true;
        errorList["host"] = i18next.t("admin.mod-email-host-error")
      }
      if (!this.state.mod.parameters["from"]) {
        hasError = true;
        errorList["from"] = i18next.t("admin.mod-email-from-error")
      }
      if (!this.state.mod.parameters["subject"]) {
        hasError = true;
        errorList["subject"] = i18next.t("admin.mod-email-subject-error")
      }
      if (!this.state.mod.parameters["body-pattern"] || !this.state.mod.parameters["body-pattern"].search("{CODE}")) {
        hasError = true;
        errorList["body-pattern"] = i18next.t("admin.mod-email-body-pattern-error")
      }
    }
    if (this.state.mod.parameters["set-password"] !== "always" && !hasMandatory) {
      hasError = true;
      errorList["has-mandatory"] = i18next.t("admin.mod-register-has-mandatory-error")
    }
    if (!hasError) {
      this.setState({errorList: {}}, () => {
         messageDispatcher.sendMessage('ModPlugin', {type: "modValid"});
      });
    } else {
      this.setState({errorList: errorList}, () => {
        messageDispatcher.sendMessage('ModPlugin', {type: "modInvalid"});
      });
    }
  }
  
  render() {
    var scopeList = [], defaultScopeList = [], schemeList = [];
    this.state.config.pattern.user.forEach((pattern) => {
      if (pattern.name === "scope") {
        pattern.listElements.forEach((scope, index) => {
          scopeList.push(<a key={index} className="dropdown-item" href="#" onClick={(e) => this.addScope(e, scope)}>{scope}</a>);
        })
      }
    });
    this.state.mod.parameters["scope"].forEach((scope, index) => {
      defaultScopeList.push(<a className="btn-icon-right" href="#" onClick={(e) => this.deleteScope(e, index)} key={index}><span className="badge badge-primary">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
    });
    var scopeJsx = 
    <div className="dropdown">
      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-register-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">{i18next.t("admin.mod-register-scope")}</button>
      <div className="dropdown-menu" aria-labelledby="mod-register-scope">
        {scopeList}
      </div>
      <div>
        {defaultScopeList}
      </div>
    </div>;
    this.state.mod.parameters["schemes"].forEach((scheme, index) => {
      var schemeModList = [];
      this.state.modSchemes.forEach((schemeMod, indexMod) => {
        var used = false;
        this.state.mod.parameters["schemes"].forEach(curScheme => {
          if (schemeMod.name === curScheme["name"]) {
            used = true;
          }
        });
        if (!used) {
          schemeModList.push(<a key={indexMod} className="dropdown-item" href="#" onClick={(e) => this.setSchemeName(e, index, schemeMod.name)}>{schemeMod.name}</a>);
        }
      });
      schemeList.push(
        <div className="form-group" key={index}>
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-register-name-"+index}>{i18next.t("admin.mod-register-scheme-name")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id={"mod-register-name-"+index} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {scheme["name"]}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-register-name">
                {schemeModList}
              </div>
            </div>
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-register-scheme-register-"+index}>{i18next.t("admin.mod-register-scheme-register")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id={"mod-register-scheme-register-"+index} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.mod-register-"+(scheme["register"]==="always"?"yes":"no"))}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-register-scheme-register">
                <a className={"dropdown-item"+(scheme["register"]==="always"?" active":"")} href="#" onClick={(e) => this.setSchemeRegister(e, index, "always")}>{i18next.t("admin.mod-register-yes")}</a>
                <a className={"dropdown-item"+(scheme["register"]==="yes"?" active":"")} href="#" onClick={(e) => this.setSchemeRegister(e, index, "yes")}>{i18next.t("admin.mod-register-no")}</a>
              </div>
            </div>
            <button className="btn btn-secondary" type="button" onClick={() => this.deleteScheme(index)}>
              <i className="fas fa-trash"></i>
            </button>
          </div>
        </div>
      );
    });

    return (
      <div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-register-session-key">{i18next.t("admin.mod-register-session-key")}</label>
            </div>
            <input type="text" className={this.state.errorList["session-key"]?"form-control is-invalid":"form-control"} id="mod-register-session-key" onChange={(e) => this.changeParam(e, "session-key")} value={this.state.mod.parameters["session-key"]} placeholder={i18next.t("admin.mod-register-session-key")} />
          </div>
          {this.state.errorList["session-key"]?<span className="error-input">{this.state.errorList["session-key"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-register-session-duration">{i18next.t("admin.mod-register-session-duration")}</label>
            </div>
            <input type="number" min="1" step="1" className={this.state.errorList["session-duration"]?"form-control is-invalid":"form-control"} id="mod-register-session-duration" onChange={(e) => this.changeParam(e, "session-duration", true)} value={this.state.mod.parameters["session-duration"]} placeholder={i18next.t("admin.mod-register-session-duration-ph")} />
          </div>
          {this.state.errorList["session-duration"]?<span className="error-input">{this.state.errorList["session-duration"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-register-set-password">{i18next.t("admin.mod-register-set-password")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-register-set-password" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.mod-register-"+this.state.mod.parameters["set-password"])}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-register-set-password">
                <a className={"dropdown-item"+(this.state.mod.parameters["set-password"]==="always"?" active":"")} href="#" onClick={(e) => this.setPassword(e, "always")}>{i18next.t("admin.mod-register-always")}</a>
                <a className={"dropdown-item"+(this.state.mod.parameters["set-password"]==="yes"?" active":"")} href="#" onClick={(e) => this.setPassword(e, "yes")}>{i18next.t("admin.mod-register-yes")}</a>
                <a className={"dropdown-item"+(this.state.mod.parameters["set-password"]==="no"?" active":"")} href="#" onClick={(e) => this.setPassword(e, "no")}>{i18next.t("admin.mod-register-no")}</a>
              </div>
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-default-scope">{i18next.t("admin.mod-register-scope-add")}</label>
            </div>
            {scopeJsx}
          </div>
          {this.state.errorList["scope"]?<span className="error-input">{this.state.errorList["scope"]}</span>:""}
        </div>
        <hr/>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <button type="button" className="btn btn-secondary" onClick={this.addScheme} disabled={this.state.mod.parameters["schemes"].length===this.state.modSchemes.length}>
                {i18next.t("admin.mod-register-add-scheme")}
              </button>
            </div>
          </div>
        </div>
        {schemeList}
        <hr/>
        <div className="form-group form-check">
          <input type="checkbox" className="form-check-input" id="mod-register-verify-email" onChange={(e) => this.toggleParam(e, "verify-email")} checked={this.state.mod.parameters["verify-email"]} />
          <label className="form-check-label" htmlFor="mod-register-verify-email">{i18next.t("admin.mod-register-verify-email")}</label>
        </div>
        <div className={"collapse"+(this.state.mod.parameters["verify-email"]?" show":"")} id="verifyEmailCollapse">
          <div className="form-group form-check">
            <input type="checkbox" disabled={!this.state.mod.parameters["verify-email"]} className="form-check-input" id="mod-register-email-is-username" onChange={(e) => this.toggleParam(e, "email-is-username")} checked={this.state.mod.parameters["email-is-username"]} />
            <label className="form-check-label" htmlFor="mod-register-email-is-username">{i18next.t("admin.mod-register-email-is-username")}</label>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-register-verification-code-length">{i18next.t("admin.mod-register-verification-code-length")}</label>
              </div>
              <input type="number" min="0" max="65536" step="1" className={this.state.errorList["verification-code-length"]?"form-control is-invalid":"form-control"} id="mod-register-verification-code-length" onChange={(e) => this.changeParam(e, "verification-code-length")} value={this.state.mod.parameters["verification-code-length"]} placeholder={i18next.t("admin.mod-register-verification-code-length-ph")} />
            </div>
            {this.state.errorList["verification-code-length"]?<span className="error-input">{this.state.errorList["verification-code-length"]}</span>:""}
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-register-verification-code-duration">{i18next.t("admin.mod-register-verification-code-duration")}</label>
              </div>
              <input type="number" min="0" max="65536" step="1" className={this.state.errorList["verification-code-duration"]?"form-control is-invalid":"form-control"} id="mod-register-verification-code-duration" onChange={(e) => this.changeParam(e, "verification-code-duration")} value={this.state.mod.parameters["verification-code-duration"]} placeholder={i18next.t("admin.mod-register-verification-code-duration-ph")} />
            </div>
            {this.state.errorList["verification-code-duration"]?<span className="error-input">{this.state.errorList["verification-code-duration"]}</span>:""}
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-register-host">{i18next.t("admin.mod-email-host")}</label>
              </div>
              <input type="text" className={this.state.errorList["host"]?"form-control is-invalid":"form-control"} id="mod-register-host" onChange={(e) => this.changeParam(e, "host")} value={this.state.mod.parameters["host"]} placeholder={i18next.t("admin.mod-email-host-ph")} />
            </div>
            {this.state.errorList["host"]?<span className="error-input">{this.state.errorList["host"]}</span>:""}
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-register-port">{i18next.t("admin.mod-email-port")}</label>
              </div>
              <input type="number" min="0" max="65536" step="1" className={this.state.errorList["port"]?"form-control is-invalid":"form-control"} id="mod-register-port" onChange={(e) => this.changeParam(e, "port", true)} value={this.state.mod.parameters["port"]} placeholder={i18next.t("admin.mod-email-port-ph")} />
            </div>
            {this.state.errorList["port"]?<span className="error-input">{this.state.errorList["port"]}</span>:""}
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="mod-register-use-tls" onChange={(e) => this.toggleParam(e, "use-tls")} checked={this.state.mod.parameters["use-tls"]||false} />
            <label className="form-check-label" htmlFor="mod-register-use-tls">{i18next.t("admin.mod-email-use-tls")}</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" disabled={!this.state.mod.parameters["use-tls"]} id="mod-register-check-certificate" onChange={(e) => this.toggleParam(e, "check-certificate")} checked={this.state.mod.parameters["check-certificate"]||false} />
            <label className="form-check-label" htmlFor="mod-register-check-certificate">{i18next.t("admin.mod-email-check-certificate")}</label>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-register-user">{i18next.t("admin.mod-email-user")}</label>
              </div>
              <input type="text" className={this.state.errorList["user"]?"form-control is-invalid":"form-control"} id="mod-register-user" onChange={(e) => this.changeParam(e, "user")} value={this.state.mod.parameters["user"]} placeholder={i18next.t("admin.mod-email-user-ph")} />
            </div>
            {this.state.errorList["user"]?<span className="error-input">{this.state.errorList["user"]}</span>:""}
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-register-password">{i18next.t("admin.mod-email-password")}</label>
              </div>
              <input type="password" className={this.state.errorList["password"]?"form-control is-invalid":"form-control"} id="mod-register-password" onChange={(e) => this.changeParam(e, "password")} value={this.state.mod.parameters["password"]} placeholder={i18next.t("admin.mod-email-password-ph")} />
            </div>
            {this.state.errorList["password"]?<span className="error-input">{this.state.errorList["password"]}</span>:""}
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-register-from">{i18next.t("admin.mod-email-from")}</label>
              </div>
              <input type="text" className={this.state.errorList["from"]?"form-control is-invalid":"form-control"} id="mod-register-from" onChange={(e) => this.changeParam(e, "from")} value={this.state.mod.parameters["from"]} placeholder={i18next.t("admin.mod-email-from-ph")} />
            </div>
            {this.state.errorList["from"]?<span className="error-input">{this.state.errorList["from"]}</span>:""}
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-register-content-type">{i18next.t("admin.mod-email-content-type")}</label>
              </div>
              <input type="text" className={this.state.errorList["content-type"]?"form-control is-invalid":"form-control"} id="mod-register-content-type" onChange={(e) => this.changeParam(e, "content-type")} value={this.state.mod.parameters["content-type"]||""} placeholder={i18next.t("admin.mod-email-content-type-ph")} />
            </div>
            {this.state.errorList["content-type"]?<span className="error-input">{this.state.errorList["content-type"]}</span>:""}
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mod-register-subject">{i18next.t("admin.mod-email-subject")}</label>
              </div>
              <input type="text" className={this.state.errorList["subject"]?"form-control is-invalid":"form-control"} id="mod-register-subject" onChange={(e) => this.changeParam(e, "subject")} value={this.state.mod.parameters["subject"]||""} placeholder={i18next.t("admin.mod-register-subject-ph")} />
            </div>
            {this.state.errorList["subject"]?<span className="error-input">{this.state.errorList["subject"]}</span>:""}
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <span className="input-group-text" >{i18next.t("admin.mod-register-body-pattern")}</span>
              </div>
              <textarea rows="5" className={this.state.errorList["body-pattern"]?"form-control is-invalid":"form-control"} id="mod-register-body-pattern" onChange={(e) => this.changeParam(e, "body-pattern")} placeholder={i18next.t("admin.mod-register-body-pattern-ph")} defaultValue={this.state.mod.parameters["body-pattern"]||""}></textarea>
            </div>
            {this.state.errorList["body-pattern"]?<span className="error-input">{this.state.errorList["body-pattern"]}</span>:""}
            <span className="badge badge-info">{i18next.t("admin.mod-register-body-pattern-doc")}</span>
          </div>
        </div>
        {this.state.errorList["has-mandatory"]?<span className="error-input">{this.state.errorList["has-mandatory"]}</span>:""}
      </div>
    );
  }
}

export default RegisterParams;
