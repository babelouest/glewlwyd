import React, { Component } from 'react';
import i18next from 'i18next';

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
      authDetails: props.authDetails,
      show: props.show,
      infoSomeScopeUnavailable: props.infoSomeScopeUnavailable
    };
    
    this.handleToggleGrantScope = this.handleToggleGrantScope.bind(this);
    this.handleGrantScope = this.handleGrantScope.bind(this);
    this.handleToggleAuthDetails = this.handleToggleAuthDetails.bind(this);
    
    messageDispatcher.subscribe('GrantScope', (message) => {
    });
	}
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config, 
      currentUser: nextProps.currentUser, 
      client: nextProps.client, 
      scope: nextProps.scope,
      authDetails: nextProps.authDetails,
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
    apiManager.glewlwydRequest("/auth/grant/" + encodeURIComponent(this.state.client.client_id), "PUT", {scope: scopeList.join(" ")})
    .then(() => {
      messageDispatcher.sendMessage('App', {type: 'GrantComplete'});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-set-grant")});
    });
  }
  
  handleToggleAuthDetails(selectedAuthDetails) {
    var authDetails = this.state.authDetails;
    authDetails.forEach((curAuthDetails) => {
      if (selectedAuthDetails.type === curAuthDetails.type) {
        curAuthDetails.consent = !curAuthDetails.consent;
        apiManager.glewlwydRequest("/" + this.state.config.params.plugin + "/rar/" + this.state.config.params.client_id + "/" + selectedAuthDetails.type + "/" + (curAuthDetails.consent?"1":"0"), "PUT")
        .then(() => {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.grant-auth-details-granted")});
        })
        .fail(() => {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-set-grant")});
        });
      }
    });
    this.setState({authDetails: authDetails});
  }
  
	render() {
    var scopeList = [], authDetails = [], authDetailsJsx;
    this.state.scope.forEach((scope, index) => {
      if (scope.name === "openid") {
        scopeList.push(
          <li className="list-group-item" key={index}>
            <div className="form-group form-check">
              <input type="checkbox" className="form-check-input" checked={true} disabled={true}/>
              <label className="form-check-label" htmlFor={"grant-" + scope.name}>{scope.display_name}</label>
            </div>
          </li>
        );
      } else {
        scopeList.push(
          <li className="list-group-item" key={index}>
            <div className="form-group form-check">
              <input type="checkbox" className="form-check-input" onChange={() => this.handleToggleGrantScope(scope)} id={"grant-" + scope.name} checked={scope.granted}/>
              <label className="form-check-label" htmlFor={"grant-" + scope.name}>{scope.display_name}</label>
            </div>
          </li>
        );
      }
    });
    var infoSomeScopeUnavailable;
    if (this.state.infoSomeScopeUnavailable) {
      infoSomeScopeUnavailable = <div className="alert alert-info" role="alert">{i18next.t("login.info-some-scope-unavailable")}</div>
    }
    this.state.authDetails.forEach((curDetails, index) => {
      var locationsList = [], actionsList = [], datatypesList = [], enrichedList = [];
      var locationsJsx, actionsJsx, datatypesJsx, enrichedJsx, typeJsx = <h5>{i18next.t("login.grant-auth-details-type", {type: curDetails.type})}</h5>, descriptionJsx;
      curDetails.locations.forEach((e, index) => {
        locationsList.push(
          <li className="list-group-item" key={index}>{e}</li>
        );
      });
      if (locationsList.length) {
        locationsJsx =
        <div>
          <h5>{i18next.t("login.grant-auth-details-locations")}</h5>
          <ul className="list-group">
            {locationsList}
          </ul>
        </div>
      }
      curDetails.actions.forEach((e, index) => {
        actionsList.push(
          <li className="list-group-item" key={index}>{e}</li>
        );
      });
      if (actionsList.length) {
        actionsJsx =
        <div>
          <h5>{i18next.t("login.grant-auth-details-actions")}</h5>
          <ul className="list-group">
            {actionsList}
          </ul>
        </div>
      }
      curDetails.datatypes.forEach((e, index) => {
        datatypesList.push(
          <li className="list-group-item" key={index}>{e}</li>
        );
      });
      if (datatypesList.length) {
        datatypesJsx =
        <div>
          <h5>{i18next.t("login.grant-auth-details-datatypes")}</h5>
          <ul className="list-group">
            {datatypesList}
          </ul>
        </div>
      }
      curDetails.enriched.forEach((e, index) => {
        var data = e;
        this.state.config.pattern.user.forEach((clientProperty) => {
          if (e === clientProperty.name) {
            data = i18next.t(clientProperty.label);
          }
        });
        enrichedList.push(
          <li className="list-group-item" key={index}>{data}</li>
        );
      });
      if (enrichedList.length) {
        enrichedJsx =
        <div>
          <h5>{i18next.t("login.grant-auth-details-enriched")}</h5>
          <ul className="list-group">
            {enrichedList}
          </ul>
        </div>
      }
      if (curDetails.description) {
        descriptionJsx = <h5>{i18next.t("login.grant-auth-details-description", {description: curDetails.description})}</h5>
      }
      authDetails.push(
        <li className="list-group-item" key={index}>
          <div className="form-group form-check">
            <input type="checkbox" 
                   className="form-check-input" 
                   onChange={() => this.handleToggleAuthDetails(curDetails)} 
                   id={"auth-details-" + curDetails.type} 
                   checked={curDetails.consent && curDetails.enabled}
                   disabled={!curDetails.enabled}/>
            <label className="form-check-label" htmlFor={"auth-details-" + curDetails.type}>{curDetails.description||curDetails.type}</label>
            <button className="btn btn-secondary btn-sm btn-icon-right" 
                    type="button" 
                    title={i18next.t("details")}
                    data-toggle="collapse" 
                    data-target={"#auth-details-collapse-" + curDetails.type} 
                    aria-expanded="false" 
                    aria-controls={"auth-details-collapse-" + curDetails.type}>
              <i className="fas fa-chevron-circle-down"></i>
            </button>
            <div className="collapse" id={"auth-details-collapse-" + curDetails.type}>
              <div className="card card-body">
                <h4>{i18next.t("login.grant-auth-details-explanation")}</h4>
                {typeJsx}
                {descriptionJsx}
                {locationsJsx}
                {actionsJsx}
                {datatypesJsx}
                {enrichedJsx}
              </div>
            </div>
          </div>
        </li>
      );
    });
    if (authDetails.length) {
      authDetailsJsx =
      <div>
        <hr/>
        <div className="row">
          <div className="col-md-12">
            <h3>{i18next.t("login.grant-auth-details-title")}</h3>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <ul className="list-group">
              {authDetails}
            </ul>
          </div>
        </div>
      </div>
    }
    return (
    <div>
      <div className="row">
        <div className="col-md-12">
          <h3>{i18next.t("login.grant-title")}</h3>
        </div>
      </div>
      <hr/>
      <div className="row">
        <div className="col-md-12">
          <h5>{i18next.t("login.grant-client-title", {client: this.state.client.name})}</h5>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <ul className="list-group">
            {scopeList}
          </ul>
        </div>
      </div>
      {authDetailsJsx}
      <hr className="glwd-hr-no-border"/>
      <div className="row">
        <div className="col-md-2">
          <h5>{i18next.t("login.grant-client-id")}</h5>
        </div>
        <div className="col-md-10">
          <h5><span className="badge badge-secondary">{this.state.client.client_id}</span></h5>
        </div>
      </div>
      <div className="row">
        <div className="col-md-2">
          <h5>{i18next.t("login.grant-client-redirect-uri")}</h5>
        </div>
        <div className="col-md-10">
          <h5><span className="badge badge-secondary">{this.state.client.redirect_uri}</span></h5>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          {infoSomeScopeUnavailable}
        </div>
      </div>
      <hr/>
      <div className="row">
        <div className="col-md-12">
          <button type="button" className="btn btn-primary" onClick={this.handleGrantScope}>{i18next.t("login.grant")}</button>
        </div>
      </div>
      <hr className="glwd-hr-no-border"/>
      <div className="row">
        <div className="col-md-12">
          <b>
            {i18next.t("login.grant-info-message")}
          </b>
        </div>
      </div>
    </div>);
  }

}

export default GrantScope;
