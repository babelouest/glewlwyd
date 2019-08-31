import React, { Component } from 'react';

class Confirm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      message: props.message,
      cb: props.callback
    }

    this.closeModal = this.closeModal.bind(this);
  }

  UNSAFE_componentWillReceiveProps(nextProps) {
    this.setState({
      title: nextProps.title,
      message: nextProps.message,
      cb: nextProps.callback
    });
  }

  closeModal(e, result) {
    if (this.state.cb) {
      this.state.cb(result);
    }
  }
  
	render() {
		return (
    <div className="modal fade" id="confirmModal" tabIndex="-1" role="dialog" aria-labelledby="confirmModalLabel" aria-hidden="true">
      <div className="modal-dialog" role="document">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title" id="confirmModalLabel">{this.state.title}</h5>
            <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeModal(e, false)}>
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div className="modal-body">
            {this.state.message}
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("modal.close")}</button>
            <button type="button" className="btn btn-primary" onClick={(e) => this.closeModal(e, true)}>{i18next.t("modal.ok")}</button>
          </div>
        </div>
      </div>
    </div>
		);
	}
}

export default Confirm;
