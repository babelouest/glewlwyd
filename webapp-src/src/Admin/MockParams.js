import React, { Component } from 'react';

class MockParams extends Component {
  constructor(props) {
    super(props);

    this.state = {
      mod: props.mod,
      role: props.role
    };
    
    this.changeMockUserValue = this.changeMockUserValue.bind(this);
    this.changeMockClientValue = this.changeMockClientValue.bind(this);
    this.changeMockSchemeValue = this.changeMockSchemeValue.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      mod: nextProps.mod,
      role: nextProps.role
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
  
  render() {
    if (this.state.role === "user") {
      return (
        <div className="form-group">
          <label htmlFor="mod-mock-username-prefix">{i18next.t("admin.mod-username-prefix")}</label>
          <input type="text" className="form-control" id="mod-mock-username-prefix" placeholder={i18next.t("admin.mod-username-prefix-ph")} maxLength="256" value={this.state.mod.parameters["username-prefix"]} onChange={(e) => this.changeMockUserValue(e)}/>
        </div>
      );
    } else if (this.state.role === "client") {
      return (
        <div className="form-group">
          <label htmlFor="mod-mock-client-id-prefix">{i18next.t("admin.mod-client-id-prefix")}</label>
          <input type="text" className="form-control" id="mod-mock-client-id-prefix" placeholder={i18next.t("admin.mod-client-id-prefix-ph")} maxLength="256" value={this.state.mod.parameters["client-id-prefix"]} onChange={(e) => this.changeMockClientValue(e)}/>
        </div>
      );
    } else if (this.state.role === "scheme") {
      return (
        <div className="form-group">
          <label htmlFor="mod-mock-scheme-value">{i18next.t("admin.mod-scheme-value")}</label>
          <input type="text" className="form-control" id="mod-mock-scheme-value" placeholder={i18next.t("admin.mod-scheme-value-ph")} maxLength="256" value={this.state.mod.parameters["mock-value"]} onChange={(e) => this.changeMockSchemeValue(e)}/>
        </div>
      );
    } else {
      return ("");
    }
  }
}

export default MockParams;
