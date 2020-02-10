import React, { Component } from 'react';
import i18next from 'i18next';

import MockParams from './MockParams';
import DatabaseParams from './DatabaseParams';
import LDAPParams from './LDAPParams';
import HTTPParams from './HTTPParams';
import EmailParams from './EmailParams';
import WebauthnParams from './WebauthnParams';
import OTPParams from './OTPParams';
import PasswordParams from './PasswordParams';
import CertificateParams from './CertificateParams';
import Oauth2Params from './Oauth2Params';

class ModEditParameters extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check
    };
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check
    });
  }
  
  render() {
    if (this.state.mod.module === "mock") {
      return <MockParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "database") {
      return <DatabaseParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "ldap") {
      return <LDAPParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "http") {
      return <HTTPParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "email") {
      return <EmailParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "webauthn") {
      return <WebauthnParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "otp") {
      return <OTPParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "retype-password") {
      return <PasswordParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "certificate") {
      return <CertificateParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "oauth2") {
      return <Oauth2Params mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else {
      return ("");
    }
  }
}

export default ModEditParameters;
