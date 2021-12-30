import React, { Component } from 'react';
import i18next from 'i18next';

import MockPluginParams from './MockPluginParams';
import GlwdOauth2Params from './GlwdOauth2Params';
import GlwdOIDCParams from './GlwdOIDCParams';
import RegisterParams from './RegisterParams';

class PluginEditParameters extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      modSchemes: props.modSchemes,
      mod: props.mod,
      role: props.role,
      check: props.check,
      miscConfig: props.miscConfig
    };
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      modSchemes: nextProps.modSchemes,
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check,
      miscConfig: nextProps.miscConfig
    });
  }
  
  render() {
    if (this.state.mod.module === "mock") {
      return <MockPluginParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "oauth2-glewlwyd") {
      return <GlwdOauth2Params mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "oidc") {
      return <GlwdOIDCParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} miscConfig={this.state.miscConfig} />
    } else if (this.state.mod.module === "register") {
      return <RegisterParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} modSchemes={this.state.modSchemes} miscConfig={this.state.miscConfig} />
    } else {
      return ("");
    }
  }
}

export default PluginEditParameters;
