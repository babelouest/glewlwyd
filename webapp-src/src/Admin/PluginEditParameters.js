import React, { Component } from 'react';

import MockPluginParams from './MockPluginParams';
import GlwdOauth2Params from './GlwdOauth2Params';
import GlwdOIDCParams from './GlwdOIDCParams';

class PluginEditParameters extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check
    };
  }
  
  UNSAFE_componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check
    });
  }
  
  render() {
    if (this.state.mod.module === "mock") {
      return <MockPluginParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "oauth2-glewlwyd") {
      return <GlwdOauth2Params mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "oidc") {
      return <GlwdOIDCParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else {
      return ("");
    }
  }
}

export default PluginEditParameters;
