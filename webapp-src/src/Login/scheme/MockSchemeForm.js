import React, { Component } from 'react';

import apiManager from '../../lib/APIManager';
import messageDispatcher from '../../lib/MessageDispatcher';

class MockSchemeForm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      currentUser: props.currentUser,
      triggerResult: false,
      mockValue: ""
    };
    
    this.triggerScheme = this.triggerScheme.bind(this);
    this.validateMockValue = this.validateMockValue.bind(this);
    this.handleChangeMockValue = this.handleChangeMockValue.bind(this);
    
    this.triggerScheme();
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser,
      triggerResult: false,
      mockValue: ""
    }, () => {
      this.triggerScheme();
    });
  }
  
  triggerScheme() {
    if (this.state.scheme && this.state.currentUser) {
      var scheme = {
        scheme_type: this.state.scheme.scheme_type,
        scheme_name: this.state.scheme.scheme_name,
        username: this.state.currentUser.username,
        value: {
          description: "This is a mock trigger"
        }
      };
      
      apiManager.glewlwydRequest("/auth/scheme/trigger/", "POST", scheme)
      .then((res) => {
        this.setState({triggerResult: res.code});
      })
      .fail((err) => {
        if (err.status === 401) {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.mock-trigger-must-register")});
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-mock-trigger")});
        }
      });
    }
  }
  
  handleChangeMockValue(e) {
    this.setState({mockValue: e.target.value});
  }
  
  validateMockValue(e) {
    e.preventDefault();
		var scheme = {
      scheme_type: this.state.scheme.scheme_type,
      scheme_name: this.state.scheme.scheme_name,
      username: this.state.currentUser.username,
			value: {
				code: this.state.mockValue
			}
		};
    
    apiManager.glewlwydRequest("/auth/", "POST", scheme)
    .then(() => {
      messageDispatcher.sendMessage('App', 'InitProfile');
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-mock-value")});
    });
  }
  
  render() {
    if (this.state.triggerResult) {
      return (
        <form action="#" id="mockSchemeForm">
          <div className="form-group">
            <h5>{i18next.t("login.enter-mock-scheme-value")}</h5>
          </div>
          <div className="form-group">
            <label htmlFor="mockValue">{i18next.t("login.mock-value-label")}</label>
            <input type="text" className="form-control" name="mockValue" id="mockValue" autoFocus="" required="" placeholder={i18next.t("login.error-mock-expected", {value: (this.state.triggerResult)})} value={this.state.mockValue||""} onChange={this.handleChangeMockValue}/>
          </div>
          <button type="submit" name="mockbut" id="mockbut" className="btn btn-primary" onClick={(e) => this.validateMockValue(e)} title={i18next.t("login.mock-value-button-title")}>{i18next.t("login.btn-ok")}</button>
        </form>
      );
    } else {
      return (<button type="button" className="btn btn-primary" onClick={this.triggerScheme}>{i18next.t("login.btn-reload")}</button>);
    }
  }
}

export default MockSchemeForm;
