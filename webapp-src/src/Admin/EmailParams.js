import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class EmailParams extends Component {
  constructor(props) {
    super(props);
    
    if (!props.mod) {
      props.mod = {parameters: {}};
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
    this.toggleUseTls = this.toggleUseTls.bind(this);
    this.toggleCheckServerCertificate = this.toggleCheckServerCertificate.bind(this);
    this.checkParameters = this.checkParameters.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    
    if (!nextProps.mod) {
      nextProps.mod = {parameters: {}};
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
    if (!this.state.mod.parameters["subject"]) {
      hasError = true;
      errorList["subject"] = i18next.t("admin.mod-email-subject-error")
    }
    if (!this.state.mod.parameters["body-pattern"] || !this.state.mod.parameters["body-pattern"].search("{CODE}")) {
      hasError = true;
      errorList["body-pattern"] = i18next.t("admin.mod-email-body-pattern-error")
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
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-code-length">{i18next.t("admin.mod-email-code-length")}</label>
            </div>
            <input type="number" min="0" max="65536" step="1" className={this.state.errorList["code-length"]?"form-control is-invalid":"form-control"} id="mod-email-code-length" onChange={(e) => this.changeParam(e, "code-length")} value={this.state.mod.parameters["code-length"]} placeholder={i18next.t("admin.mod-email-code-length-ph")} />
          </div>
          {this.state.errorList["code-length"]?<span className="error-input">{i18next.t(this.state.errorList["code-length"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-code-duration">{i18next.t("admin.mod-email-code-duration")}</label>
            </div>
            <input type="number" min="0" max="65536" step="1" className={this.state.errorList["code-duration"]?"form-control is-invalid":"form-control"} id="mod-email-code-duration" onChange={(e) => this.changeParam(e, "code-duration")} value={this.state.mod.parameters["code-duration"]} placeholder={i18next.t("admin.mod-email-code-duration-ph")} />
          </div>
          {this.state.errorList["code-duration"]?<span className="error-input">{i18next.t(this.state.errorList["code-duration"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-host">{i18next.t("admin.mod-email-host")}</label>
            </div>
            <input type="text" className={this.state.errorList["host"]?"form-control is-invalid":"form-control"} id="mod-email-host" onChange={(e) => this.changeParam(e, "host")} value={this.state.mod.parameters["host"]} placeholder={i18next.t("admin.mod-email-host-ph")} />
          </div>
          {this.state.errorList["host"]?<span className="error-input">{i18next.t(this.state.errorList["host"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-port">{i18next.t("admin.mod-email-port")}</label>
            </div>
            <input type="number" min="0" max="65536" step="1" className={this.state.errorList["port"]?"form-control is-invalid":"form-control"} id="mod-email-port" onChange={(e) => this.changeParam(e, "port", true)} value={this.state.mod.parameters["port"]} placeholder={i18next.t("admin.mod-email-port-ph")} />
          </div>
          {this.state.errorList["port"]?<span className="error-input">{i18next.t(this.state.errorList["port"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-use-tls">{i18next.t("admin.mod-email-use-tls")}</label>
            </div>
            <div className="input-group-text">
              <input type="checkbox" className="form-control" id="mod-email-use-tls" onChange={(e) => this.toggleUseTls()} checked={this.state.mod.parameters["use-tls"]||false} />
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-check-certificate">{i18next.t("admin.mod-email-check-certificate")}</label>
            </div>
            <div className="input-group-text">
              <input type="checkbox" className="form-control" disabled={!this.state.mod.parameters["use-tls"]} className="form-control" id="mod-email-check-certificate" onChange={(e) => this.toggleCheckServerCertificate()} checked={this.state.mod.parameters["check-certificate"]||false} />
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-user">{i18next.t("admin.mod-email-user")}</label>
            </div>
            <input type="text" className={this.state.errorList["user"]?"form-control is-invalid":"form-control"} id="mod-email-user" onChange={(e) => this.changeParam(e, "user")} value={this.state.mod.parameters["user"]} placeholder={i18next.t("admin.mod-email-user-ph")} />
          </div>
          {this.state.errorList["user"]?<span className="error-input">{i18next.t(this.state.errorList["user"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-password">{i18next.t("admin.mod-email-password")}</label>
            </div>
            <input type="password" className={this.state.errorList["password"]?"form-control is-invalid":"form-control"} id="mod-email-password" onChange={(e) => this.changeParam(e, "password")} value={this.state.mod.parameters["password"]} placeholder={i18next.t("admin.mod-email-password-ph")} />
          </div>
          {this.state.errorList["password"]?<span className="error-input">{i18next.t(this.state.errorList["password"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-from">{i18next.t("admin.mod-email-from")}</label>
            </div>
            <input type="text" className={this.state.errorList["from"]?"form-control is-invalid":"form-control"} id="mod-email-from" onChange={(e) => this.changeParam(e, "from")} value={this.state.mod.parameters["from"]} placeholder={i18next.t("admin.mod-email-from-ph")} />
          </div>
          {this.state.errorList["from"]?<span className="error-input">{i18next.t(this.state.errorList["from"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-email-subject">{i18next.t("admin.mod-email-subject")}</label>
            </div>
            <input type="text" className={this.state.errorList["subject"]?"form-control is-invalid":"form-control"} id="mod-email-subject" onChange={(e) => this.changeParam(e, "subject")} value={this.state.mod.parameters["subject"]||""} placeholder={i18next.t("admin.mod-email-subject-ph")} />
          </div>
          {this.state.errorList["subject"]?<span className="error-input">{i18next.t(this.state.errorList["subject"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <span className="input-group-text" >{i18next.t("admin.mod-email-body-pattern")}</span>
            </div>
            <textarea className={this.state.errorList["body-pattern"]?"form-control is-invalid":"form-control"} id="mod-email-body-pattern" onChange={(e) => this.changeParam(e, "body-pattern")} placeholder={i18next.t("admin.mod-email-body-pattern-ph")} >{this.state.mod.parameters["body-pattern"]||""}</textarea>
          </div>
          {this.state.errorList["body-pattern"]?<span className="error-input">{i18next.t(this.state.errorList["body-pattern"])}</span>:""}
        </div>
      </div>
    );
  }
}

export default EmailParams;
