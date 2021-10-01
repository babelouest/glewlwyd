import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';

class EmailParams extends Component {
  constructor(props) {
    super(props);
    
    if (!props.mod) {
      props.mod = {parameters: {}};
    }
    
    if (props.mod.parameters.host === undefined) {
      props.mod.parameters.host = "";
    }
    
    if (props.mod.parameters.user === undefined) {
      props.mod.parameters.user = "";
    }
    
    if (props.mod.parameters.password === undefined) {
      props.mod.parameters.password = "";
    }
    
    if (props.mod.parameters["use-tls"] === undefined) {
      props.mod.parameters["use-tls"] = false;
    }
    
    if (props.mod.parameters["check-certificate"] === undefined) {
      props.mod.parameters["check-certificate"] = true;
    }
    
    if (!props.mod.parameters["code-length"]) {
      props.mod.parameters["code-length"] = 6;
    }

    if (!props.mod.parameters["code-duration"]) {
      props.mod.parameters["code-duration"] = 600;
    }

    if (!props.mod.parameters["port"]) {
      props.mod.parameters["port"] = 0;
    }

    if (props.mod.parameters.from === undefined) {
      props.mod.parameters.from = "";
    }
    
    if (props.mod.parameters["user-lang-property"] === undefined) {
      props.mod.parameters["user-lang-property"] = "lang";
    }

    if (props.mod.parameters["content-type"] === undefined) {
      props.mod.parameters["content-type"] = "text/plain; charset=utf-8";
    }

    if (!props.mod.parameters["templates"]) {
      props.mod.parameters["templates"] = {};
      props.mod.parameters["templates"][i18next.language] = {subject: props.mod.parameters.subject||"", "body-pattern": props.mod.parameters["body-pattern"]||"", defaultLang: true}
    }

    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check,
      hasError: false,
      errorList: {},
      currentLang: i18next.language,
      newLang: ""
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.changeParam = this.changeParam.bind(this);
    this.toggleUseTls = this.toggleUseTls.bind(this);
    this.toggleCheckServerCertificate = this.toggleCheckServerCertificate.bind(this);
    this.checkParameters = this.checkParameters.bind(this);
    this.changeLang = this.changeLang.bind(this);
    this.toggleLangDefault = this.toggleLangDefault.bind(this);
    this.changeNewLang = this.changeNewLang.bind(this);
    this.addLang = this.addLang.bind(this);
    this.removeLang = this.removeLang.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    
    if (!nextProps.mod) {
      nextProps.mod = {parameters: {}};
    }
    
    if (nextProps.mod.parameters.host === undefined) {
      nextProps.mod.parameters.host = "";
    }
    
    if (nextProps.mod.parameters.user === undefined) {
      nextProps.mod.parameters.user = "";
    }
    
    if (nextProps.mod.parameters.password === undefined) {
      nextProps.mod.parameters.password = "";
    }
    
    if (nextProps.mod.parameters["use-tls"] === undefined) {
      nextProps.mod.parameters["use-tls"] = false;
    }
    
    if (nextProps.mod.parameters["check-certificate"] === undefined) {
      nextProps.mod.parameters["check-certificate"] = true;
    }
    
    if (!nextProps.mod.parameters["code-length"]) {
      nextProps.mod.parameters["code-length"] = 6;
    }

    if (!nextProps.mod.parameters["code-duration"]) {
      nextProps.mod.parameters["code-duration"] = 600;
    }

    if (!nextProps.mod.parameters["port"]) {
      nextProps.mod.parameters["port"] = 0;
    }

    if (nextProps.mod.parameters.from === undefined) {
      nextProps.mod.parameters.from = "";
    }
    
    if (nextProps.mod.parameters["user-lang-property"] === undefined) {
      nextProps.mod.parameters["user-lang-property"] = "lang";
    }

    if (nextProps.mod.parameters["content-type"] === undefined) {
      nextProps.mod.parameters["content-type"] = "text/plain; charset=utf-8";
    }

    if (!nextProps.mod.parameters["templates"]) {
      nextProps.mod.parameters["templates"] = {};
      nextProps.mod.parameters["templates"][i18next.language] = {subject: nextProps.mod.parameters.subject||"", "body-pattern": nextProps.mod.parameters["body-pattern"]||"", defaultLang: true}
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
  
  toggleUseTls() {
    var mod = this.state.mod;
    mod.parameters["use-tls"] = !mod.parameters["use-tls"];
    this.setState({mod: mod});
  }
  
  toggleCheckServerCertificate() {
    var mod = this.state.mod;
    mod.parameters["check-certificate"] = !mod.parameters["check-certificate"];
    this.setState({mod: mod});
  }
  
  changeNewLang(e) {
    this.setState({newLang: e.target.value});
  }
  
  addLang() {
    var mod = this.state.mod;
    var found = false;
    Object.keys(mod.parameters.templates).forEach(lang => {
      if (lang === this.state.newLang) {
        found = true;
      }
    });
    if (!found && this.state.newLang) {
      mod.parameters.templates[this.state.newLang] = {subject: "", "body-pattern": "", defaultLang: false};
      this.setState({mod: mod, newLang: "", currentLang: this.state.newLang});
    }
  }
  
  removeLang(lang) {
    var mod = this.state.mod;
    var currentLang = false;
    delete(mod.parameters.templates[lang]);
    if (lang == this.state.currentLang) {
      Object.keys(mod.parameters.templates).forEach(lang => {
        if (!currentLang) {
          currentLang = lang;
        }
      });
      this.setState({mod: mod, currentLang: currentLang});
    } else {
      this.setState({mod: mod});
    }
  }
  
  changeLang(e, lang) {
    this.setState({currentLang: lang});
  }
  
  changeTemplate(e, param) {
    var mod = this.state.mod;
    mod.parameters.templates[this.state.currentLang][param] = e.target.value;
    this.setState({mod: mod});
  }
  
  toggleLangDefault() {
    var mod = this.state.mod;
    Object.keys(mod.parameters.templates).forEach(objKey => {
      mod.parameters.templates[objKey].defaultLang = (objKey === this.state.currentLang);
    });
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["code-length"]) {
      hasError = true;
      errorList["code-length"] = i18next.t("admin.mod-email-code-length-error")
    }
    if (!this.state.mod.parameters["code-duration"]) {
      hasError = true;
      errorList["code-duration"] = i18next.t("admin.mod-email-code-duration-error")
    }
    if (!this.state.mod.parameters["host"]) {
      hasError = true;
      errorList["host"] = i18next.t("admin.mod-email-host-error")
    }
    if (!this.state.mod.parameters["from"]) {
      hasError = true;
      errorList["from"] = i18next.t("admin.mod-email-from-error")
    }
    if (!this.state.mod.parameters["content-type"]) {
      hasError = true;
      errorList["content-type"] = i18next.t("admin.mod-email-content-type-error")
    }
    if (!this.state.mod.parameters["user-lang-property"]) {
      hasError = true;
      errorList["user-lang-property"] = i18next.t("admin.mod-email-user-lang-property-error")
    }
    errorList["subject"] = "";
    errorList["body-pattern"] = "";
    Object.keys(this.state.mod.parameters.templates).forEach(lang => {
      if (!this.state.mod.parameters.templates[lang]["subject"]) {
        hasError = true;
        errorList["subject"] += i18next.t("admin.mod-email-subject-error", {lang: lang})
      }
      if (this.state.mod.parameters.templates[lang]["body-pattern"].search("{CODE}") === -1) {
        hasError = true;
        errorList["body-pattern"] += i18next.t("admin.mod-email-body-pattern-error", {lang: lang})
      }
    });
    if (!hasError) {
      this.setState({errorList: {}}, () => {
        messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
      });
    } else {
      this.setState({errorList: errorList});
    }
  }
  
  render() {
    var langList = [];
    langList.push(
    <div key={-2} className="form-group">
      <div className="input-group mb-3">
        <input type="text" className="form-control" id="mod-email-new-lang" placeholder={i18next.t("admin.mod-email-new-lang-ph")} value={this.state.newLang} onChange={(e) => this.changeNewLang(e)} />
        <div className="input-group-append">
          <button type="button" onClick={this.addLang} className="btn btn-outline-primary">{i18next.t("admin.mod-email-new-lang-add")}</button>
        </div>
      </div>
    </div>
    );
    langList.push(<div key={-1} className="dropdown-divider"></div>);
    Object.keys(this.state.mod.parameters.templates).forEach((lang, index) => {
      langList.push(
      <div key={index*2} className="btn-group btn-group-justified">
        <button type="button" className="btn btn-primary" disabled={true}>{lang}</button>
        <button type="button" onClick={(e) => this.removeLang(lang)} className="btn btn-primary" disabled={this.state.mod.parameters.templates[lang].defaultLang}>{i18next.t("admin.mod-email-new-lang-remove")}</button>
        <button type="button" onClick={(e) => this.changeLang(e, lang)} className="btn btn-primary">{i18next.t("admin.mod-email-new-lang-select")}</button>
      </div>
      );
      langList.push(<div key={(index*2)+1} className="dropdown-divider"></div>);
    });
    var template = this.state.mod.parameters.templates[this.state.currentLang]||{};
    return (
      <div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-code-length">{i18next.t("admin.mod-email-code-length")}</label>
            </div>
            <input type="number" min="0" max="65536" step="1" className={this.state.errorList["code-length"]?"form-control is-invalid":"form-control"} id="mod-email-code-length" onChange={(e) => this.changeParam(e, "code-length")} value={this.state.mod.parameters["code-length"]} placeholder={i18next.t("admin.mod-email-code-length-ph")} />
          </div>
          {this.state.errorList["code-length"]?<span className="error-input">{this.state.errorList["code-length"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-code-duration">{i18next.t("admin.mod-email-code-duration")}</label>
            </div>
            <input type="number" min="0" max="65536" step="1" className={this.state.errorList["code-duration"]?"form-control is-invalid":"form-control"} id="mod-email-code-duration" onChange={(e) => this.changeParam(e, "code-duration")} value={this.state.mod.parameters["code-duration"]} placeholder={i18next.t("admin.mod-email-code-duration-ph")} />
          </div>
          {this.state.errorList["code-duration"]?<span className="error-input">{this.state.errorList["code-duration"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-host">{i18next.t("admin.mod-email-host")}</label>
            </div>
            <input type="text" className={this.state.errorList["host"]?"form-control is-invalid":"form-control"} id="mod-email-host" onChange={(e) => this.changeParam(e, "host")} value={this.state.mod.parameters["host"]} placeholder={i18next.t("admin.mod-email-host-ph")} />
          </div>
          {this.state.errorList["host"]?<span className="error-input">{this.state.errorList["host"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-port">{i18next.t("admin.mod-email-port")}</label>
            </div>
            <input type="number" min="0" max="65536" step="1" className={this.state.errorList["port"]?"form-control is-invalid":"form-control"} id="mod-email-port" onChange={(e) => this.changeParam(e, "port", true)} value={this.state.mod.parameters["port"]} placeholder={i18next.t("admin.mod-email-port-ph")} />
          </div>
          {this.state.errorList["port"]?<span className="error-input">{this.state.errorList["port"]}</span>:""}
        </div>
        <div className="form-group form-check">
          <input type="checkbox" className="form-check-input" id="mod-email-use-tls" onChange={(e) => this.toggleUseTls()} checked={this.state.mod.parameters["use-tls"]||false} />
          <label className="form-check-label" htmlFor="mod-email-use-tls">{i18next.t("admin.mod-email-use-tls")}</label>
        </div>
        <div className="form-group form-check">
          <input type="checkbox" className="form-check-input" disabled={!this.state.mod.parameters["use-tls"]} id="mod-email-check-certificate" onChange={(e) => this.toggleCheckServerCertificate()} checked={this.state.mod.parameters["check-certificate"]||false} />
          <label className="form-check-label" htmlFor="mod-email-check-certificate">{i18next.t("admin.mod-email-check-certificate")}</label>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-user">{i18next.t("admin.mod-email-user")}</label>
            </div>
            <input type="text" className={this.state.errorList["user"]?"form-control is-invalid":"form-control"} id="mod-email-user" onChange={(e) => this.changeParam(e, "user")} value={this.state.mod.parameters["user"]} placeholder={i18next.t("admin.mod-email-user-ph")} />
          </div>
          {this.state.errorList["user"]?<span className="error-input">{this.state.errorList["user"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-password">{i18next.t("admin.mod-email-password")}</label>
            </div>
            <input type="password" className={this.state.errorList["password"]?"form-control is-invalid":"form-control"} id="mod-email-password" onChange={(e) => this.changeParam(e, "password")} value={this.state.mod.parameters["password"]} placeholder={i18next.t("admin.mod-email-password-ph")} />
          </div>
          {this.state.errorList["password"]?<span className="error-input">{this.state.errorList["password"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-from">{i18next.t("admin.mod-email-from")}</label>
            </div>
            <input type="text" className={this.state.errorList["from"]?"form-control is-invalid":"form-control"} id="mod-email-from" onChange={(e) => this.changeParam(e, "from")} value={this.state.mod.parameters["from"]} placeholder={i18next.t("admin.mod-email-from-ph")} />
          </div>
          {this.state.errorList["from"]?<span className="error-input">{this.state.errorList["from"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-content-type">{i18next.t("admin.mod-email-content-type")}</label>
            </div>
            <input type="text" className={this.state.errorList["content-type"]?"form-control is-invalid":"form-control"} id="mod-content-type-from" onChange={(e) => this.changeParam(e, "content-type")} value={this.state.mod.parameters["content-type"]} placeholder={i18next.t("admin.mod-email-content-type-ph")} />
          </div>
          {this.state.errorList["content-type"]?<span className="error-input">{this.state.errorList["content-type"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-user-lang-property">{i18next.t("admin.mod-email-user-lang-property")}</label>
            </div>
            <input type="text" className={this.state.errorList["user-lang-property"]?"form-control is-invalid":"form-control"} id="mod-email-user-lang-property" onChange={(e) => this.changeParam(e, "user-lang-property")} value={this.state.mod.parameters["user-lang-property"]} placeholder={i18next.t("admin.mod-email-user-lang-property-ph")} />
          </div>
          {this.state.errorList["user-lang-property"]?<span className="error-input">{this.state.errorList["user-lang-property"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-lang">{i18next.t("admin.mod-email-lang")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-email-lang" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {this.state.currentLang}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-email-lang">
                {langList}
              </div>
            </div>
          </div>
        </div>
        <div className="form-group form-check">
          <input type="checkbox" className="form-check-input" id="mod-email-lang-default" onChange={(e) => this.toggleLangDefault()} checked={template.defaultLang} />
          <label className="form-check-label" htmlFor="mod-email-lang-default">{i18next.t("admin.mod-email-lang-default")}</label>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-subject">{i18next.t("admin.mod-email-subject")}</label>
            </div>
            <input type="text" className={this.state.errorList["subject"]?"form-control is-invalid":"form-control"} id="mod-email-subject" onChange={(e) => this.changeTemplate(e, "subject")} value={template["subject"]} placeholder={i18next.t("admin.mod-email-subject-ph")} />
          </div>
          {this.state.errorList["subject"]?<span className="error-input">{this.state.errorList["subject"]}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <span className="input-group-text" >{i18next.t("admin.mod-email-body-pattern")}</span>
            </div>
            <textarea className={this.state.errorList["body-pattern"]?"form-control is-invalid":"form-control"} id="mod-email-body-pattern" onChange={(e) => this.changeTemplate(e, "body-pattern")} placeholder={i18next.t("admin.mod-email-body-pattern-ph")} value={template["body-pattern"]}></textarea>
          </div>
          {this.state.errorList["body-pattern"]?<span className="error-input">{this.state.errorList["body-pattern"]}</span>:""}
        </div>
      </div>
    );
  }
}

export default EmailParams;
