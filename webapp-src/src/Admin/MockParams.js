import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class MockParams extends Component {
  constructor(props) {
    super(props);

    this.state = {
      mod: props.mod,
      role: props.role,
      check: props.check,
      hasError: false
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.changeMockUserValue = this.changeMockUserValue.bind(this);
    this.changeMockClientValue = this.changeMockClientValue.bind(this);
    this.changeMockSchemeValue = this.changeMockSchemeValue.bind(this);
    this.checkParameters = this.checkParameters.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
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
  
  changeMockUserValue(e) {
    var mod = this.state.mod;
    mod.parameters["username-prefix"] = e.target.value;
    this.setState({mod: mod});
  }
  
  changeMockClientValue(e) {
    var mod = this.state.mod;
    mod.parameters["client-id-prefix"] = e.target.value;
    this.setState({mod: mod});
  }
  
  changeMockSchemeValue(e) {
    var mod = this.state.mod;
    mod.parameters["mock-value"] = e.target.value;
    this.setState({mod: mod});
  }
  
  checkParameters() {
    if (this.state.role === "user") {
      if (!this.state.mod.parameters["username-prefix"]) {
        this.setState({hasError: true});
      } else {
        this.setState({hasError: false});
        messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
      }
    } else if (this.state.role === "client") {
      if (!this.state.mod.parameters["client-id-prefix"]) {
        this.setState({hasError: true});
      } else {
        this.setState({hasError: false});
        messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
      }
    } else if (this.state.role === "scheme") {
      if (!this.state.mod.parameters["mock-value"]) {
        this.setState({hasError: true});
      } else {
        this.setState({hasError: false});
        messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
      }
    }
  }
  
  render() {
    var errorJsx = "", validInput = "";
    if (this.state.role === "user") {
      if (this.state.hasError) {
        validInput = " is-invalid";
        errorJsx = <span className="error-input">{i18next.t("admin.mod-mock-username-prefix-required")}</span>
      }
      return (
        <div className="form-group">
          <label htmlFor="mod-mock-username-prefix">{i18next.t("admin.mod-username-prefix")}</label>
          <input type="text" className={"form-control" + validInput} id="mod-mock-username-prefix" placeholder={i18next.t("admin.mod-username-prefix-ph")} maxLength="256" value={this.state.mod.parameters["username-prefix"]||""} onChange={(e) => this.changeMockUserValue(e)}/>
          {errorJsx}
        </div>
      );
    } else if (this.state.role === "client") {
      if (this.state.hasError) {
        validInput = " is-invalid";
        errorJsx = <span className="error-input">{i18next.t("admin.mod-mock-client-id-prefix-required")}</span>
      }
      return (
        <div className="form-group">
          <label htmlFor="mod-mock-client-id-prefix">{i18next.t("admin.mod-client-id-prefix")}</label>
          <input type="text" className={"form-control" + validInput} id="mod-mock-client-id-prefix" placeholder={i18next.t("admin.mod-client-id-prefix-ph")} maxLength="256" value={this.state.mod.parameters["client-id-prefix"]||""} onChange={(e) => this.changeMockClientValue(e)}/>
          {errorJsx}
        </div>
      );
    } else if (this.state.role === "scheme") {
      if (this.state.hasError) {
        validInput = " is-invalid";
        errorJsx = <span className="error-input">{i18next.t("admin.mod-mock-scheme-value-required")}</span>
      }
      return (
        <div className="form-group">
          <label htmlFor="mod-mock-scheme-value">{i18next.t("admin.mod-scheme-value")}</label>
          <input type="text" className={"form-control" + validInput} id="mod-mock-scheme-value" placeholder={i18next.t("admin.mod-scheme-value-ph")} maxLength="256" value={this.state.mod.parameters["mock-value"]||""} onChange={(e) => this.changeMockSchemeValue(e)}/>
          {errorJsx}
        </div>
      );
    } else {
      return ("");
    }
  }
}

export default MockParams;
