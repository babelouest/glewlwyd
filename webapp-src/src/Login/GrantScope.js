import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

class GrantScope extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      currentUser: props.currentUser,
      client: props.client,
      scope: props.scope,
      show: props.show,
      infoSomeScopeUnavailable: props.infoSomeScopeUnavailable
    };
    
    this.handleToggleGrantScope = this.handleToggleGrantScope.bind(this);
    this.handleGrantScope = this.handleGrantScope.bind(this);
    
    messageDispatcher.subscribe('GrantScope', (message) => {
    });
	}
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config, 
      currentUser: nextProps.currentUser, 
      client: nextProps.client, 
      scope: nextProps.scope,
      show: nextProps.show,
      infoSomeScopeUnavailable: nextProps.infoSomeScopeUnavailable
    });
  }

  handleToggleGrantScope(scope) {
    var scopeList = this.state.scope;
    scopeList.forEach((curScope) => {
      if (curScope.name === scope.name) {
        curScope.granted = !curScope.granted;
      }
    });
    this.setState({scope: scopeList});
  }

  handleGrantScope() {
    var scopeList = [];
    this.state.scope.forEach((scope) => {
      if (scope.granted) {
        scopeList.push(scope.name);
      }
    });
    apiManager.glewlwydRequest("/auth/grant/" + encodeURI(this.state.client.client_id), "PUT", {scope: scopeList.join(" ")})
    .then(() => {
      messageDispatcher.sendMessage('App', {type: 'GrantComplete'});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-set-grant")});
    });
  }
  
	render() {
    var scopeList = [];
    this.state.scope.forEach((scope, index) => {
      scopeList.push(
        <li className="list-group-item" key={index}>
          <div className="form-check">
            <div className="input-group mb-3">
              <div className="input-group-prepend input-group-text">
                <input type="checkbox" className="form-control" onChange={() => this.handleToggleGrantScope(scope)} id={"grant-" + scope.name} checked={scope.granted}/>
              </div>
              <div className="input-group-text">
                <label className="form-check-label" htmlFor={"grant-" + scope.name}>{scope.name}</label>
              </div>
            </div>
          </div>
        </li>
      );
    });
    var infoSomeScopeUnavailable;
    if (this.state.infoSomeScopeUnavailable) {
      infoSomeScopeUnavailable = <div className="alert alert-info" role="alert">{i18next.t("login.info-some-scope-unavailable")}</div>
    }
    return (
    <div>
      <div className="row">
        <div className="col-md-12">
          <h4>{i18next.t("login.grant-title", {client: this.state.client.name})}</h4>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <ul className="list-group">
            {scopeList}
          </ul>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          {infoSomeScopeUnavailable}
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <button type="button" className="btn btn-primary" onClick={this.handleGrantScope}>{i18next.t("login.grant")}</button>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <hr/>
        </div>
      </div>
    </div>);
  }

}

export default GrantScope;
